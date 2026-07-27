"""DNS R14: behavior-corroborated severity and additive evidence.

The end-to-end cases keep the lexical score below the shipped 1.8 high bar so
the former score-only ladder cannot make a resolution-positive case pass.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from sigwood.common import clustering
from sigwood.common.finding import DetectorContext, RunSummary, Severity
from sigwood.common.output import Reporter
from sigwood.detectors import dns as dns_mod
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs._evidence import curated_evidence
from sigwood.outputs.html import render_report_html
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.pdf import PdfHandler
from sigwood.outputs.text import TextHandler


_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)
_WINDOW = (_NOW, _NOW)
_MID_LABEL = "a3f7bc19"


class _AllNoise:
    def __init__(self, **kwargs) -> None:
        pass

    def fit_predict(self, matrix: np.ndarray) -> np.ndarray:
        return np.full(matrix.shape[0], -1, dtype=int)


def _extract(query: str) -> SimpleNamespace:
    parts = query.rstrip(".").split(".")
    return SimpleNamespace(
        domain=parts[-2],
        suffix=parts[-1],
        subdomain=".".join(parts[:-2]),
        top_domain_under_public_suffix=".".join(parts[-2:]),
    )


@pytest.fixture(autouse=True)
def _deterministic_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clustering, "_CLUSTERING_ISOLATE_ENABLED", False)
    monkeypatch.setattr(clustering, "HDBSCAN", _AllNoise)
    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _extract)


def _zeek_findings(
    rows: list[dict],
    *,
    threshold: float = 1.5,
) -> list:
    return dns_mod.run(DetectorContext(
        logs={"dns*.log*": pd.DataFrame(rows)},
        config={
            "min_cluster_size": 2,
            "min_samples": 1,
            "threshold": threshold,
            "thresh_high_entropy": 1.8,
            "scan_dense_clusters": False,
        },
        allowlist=None,
        data_window=_WINDOW,
    ))


def _singleton_rows(rcodes: list[int], *, sources: int = 1) -> list[dict]:
    query = f"{_MID_LABEL}.signal.example"
    return [
        {
            "ts": float(i),
            "src": f"192.0.2.{(i % sources) + 1}",
            "query": query,
            "rcode": rcode,
        }
        for i, rcode in enumerate(rcodes)
    ]


@pytest.mark.parametrize(
    ("rcodes", "expected_severity", "expected_basis", "fraction", "count"),
    [
        ([3, 3, 0, 0], Severity.HIGH, ["resolution-outcome"], 0.5, 2),
        ([3, 3, 0, 0, 0], Severity.MEDIUM, [], 0.4, 2),
        ([3, 0], Severity.MEDIUM, [], 0.5, 1),
        ([3, 0, 0], Severity.MEDIUM, [], 1 / 3, 1),
        ([3], Severity.MEDIUM, [], 1.0, 1),
    ],
)
def test_resolution_ladder_boundaries_through_run(
    rcodes,
    expected_severity,
    expected_basis,
    fraction,
    count,
) -> None:
    assert 1.5 <= dns_mod.entropy(_MID_LABEL) < 1.8

    findings = _zeek_findings(_singleton_rows(rcodes))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == expected_severity
    assert finding.evidence["severity_basis"] == expected_basis
    assert finding.evidence["nxdomain_fraction"] == round(fraction, 4)
    assert finding.evidence["nxdomain_count"] == count


def test_resolution_outcome_applies_to_group_and_singleton_through_run() -> None:
    rows = [
        {"ts": 1.0, "src": "192.0.2.1", "query": "a3f7bc19.group.example", "rcode": 3},
        {"ts": 2.0, "src": "192.0.2.2", "query": "m8x2q9n.group.example", "rcode": 3},
        {"ts": 3.0, "src": "192.0.2.3", "query": "a3f7bc19.solo.example", "rcode": 3},
        {"ts": 4.0, "src": "192.0.2.4", "query": "a3f7bc19.solo.example", "rcode": 3},
    ]

    findings = _zeek_findings(rows)

    assert len(findings) == 2
    group = next(f for f in findings if "subdomain_count" in f.evidence)
    singleton = next(f for f in findings if "subdomain_count" not in f.evidence)
    for finding in (group, singleton):
        assert finding.severity == Severity.HIGH
        assert finding.evidence["severity_basis"] == ["resolution-outcome"]
        assert finding.evidence["nxdomain_fraction"] == 1.0
        assert finding.evidence["nxdomain_count"] == 2
        assert "2 lookups under this name failed to resolve (100% of the total)." in (
            finding.description
        )
    assert group.description == (
        "Registrable domain group.example has 2 subdomains in the DNS noise "
        "cluster with elevated label scores. 2 lookups under this name failed "
        "to resolve (100% of the total)."
    )
    assert singleton.description == (
        "Domain a3f7bc19.solo.example appears in the DNS noise cluster with "
        "label score 1.7704. 2 lookups under this name failed to resolve "
        "(100% of the total)."
    )
    for finding in (group, singleton):
        curated = curated_evidence(finding)
        assert curated["severity_basis"] == ["resolution-outcome"]
        assert curated["nxdomain_fraction"] == 1.0
        assert curated["nxdomain_count"] == 2


def test_lexical_score_is_a_gate_not_a_high_severity_leg() -> None:
    no_behavior = _zeek_findings(_singleton_rows([0, 0]))
    below_gate = _zeek_findings(_singleton_rows([3, 3]), threshold=1.8)

    assert len(no_behavior) == 1
    assert no_behavior[0].severity == Severity.MEDIUM
    assert no_behavior[0].evidence["severity_basis"] == []
    assert no_behavior[0].description.endswith(
        "The label score is the only signal - nothing in the query behavior "
        "corroborates it."
    )
    assert below_gate == []


def test_query_volume_and_client_spread_remain_evidence_only() -> None:
    findings = _zeek_findings(_singleton_rows([0] * 40, sources=40))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence["query_count"] == 40
    assert finding.evidence["unique_sources"] == 40
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["severity_basis"] == []


def test_pihole_group_has_no_rcode_column_and_cannot_be_high() -> None:
    rows = []
    for query, source in (
        ("a3f7bc19.group.example", "192.0.2.1"),
        ("m8x2q9n.group.example", "192.0.2.2"),
    ):
        rows.extend([
            {"query": query, "event_type": "query", "src": source, "qtype": "A"},
            {"query": query, "event_type": "query", "src": source, "qtype": "A"},
        ])
    rows.append({
        "query": "a3f7bc19.group.example",
        "event_type": "gravity_blocked",
        "src": None,
        "qtype": None,
    })

    findings = dns_mod.run(DetectorContext(
        logs={"pihole*.log*": pd.DataFrame(rows)},
        config={
            "threshold": 1.5,
            "thresh_high_entropy": 1.8,
            "pihole": {"min_cluster_size": 2, "min_samples": 1},
        },
        allowlist=None,
        data_window=_WINDOW,
    ))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence["source"] == "pihole"
    assert finding.evidence["was_blocked"] is True
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["severity_basis"] == []
    assert "nxdomain_fraction" not in finding.evidence
    assert "nxdomain_count" not in finding.evidence
    assert finding.description.endswith(
        "The label score is the only signal - nothing in the query behavior "
        "corroborates it."
    )
    curated = curated_evidence(finding)
    assert curated["severity_basis"] == []
    assert "nxdomain_fraction" not in curated
    assert "nxdomain_count" not in curated


def test_nxdomain_stats_handles_numpy_keys_unknown_keys_and_bad_counts() -> None:
    stats = dns_mod._nxdomain_stats({
        np.int64(3): np.int64(2),
        np.float64(0): np.int64(2),
    })
    unknown = dns_mod._nxdomain_stats({"other": 2, np.nan: 2, 3: 2})
    malformed = dns_mod._nxdomain_stats({3: "bad", 0: 2})

    assert stats == (0.5, 2)
    assert unknown == (2 / 6, 2)
    assert malformed == (0.0, 0)
    assert dns_mod._nxdomain_stats({0: 4}) == (0.0, 0)
    assert dns_mod._nxdomain_stats(None) is None
    assert dns_mod._nxdomain_stats([]) is None
    assert dns_mod._nxdomain_stats({}) is None
    assert dns_mod._nxdomain_stats({3: 0}) is None


def test_severity_uses_unrounded_fraction_at_the_half_boundary() -> None:
    severity, basis = dns_mod._severity_for(
        (0.49996, 2), dense_origin=False,
    )

    assert round(0.49996, 4) == 0.5
    assert severity == Severity.MEDIUM
    assert basis == []


def _summary() -> RunSummary:
    return RunSummary(
        data_window=_WINDOW,
        record_counts={"dns*.log*": 4},
        data_size_bytes=100,
        detectors_run=["dns"],
        detectors_skipped={},
    )


def test_r14_evidence_survives_every_sink_without_new_unsafe_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _zeek_findings(_singleton_rows([3, 3, 0, 0]))[0]
    finding.evidence["rcode_distribution"]["bad\x1b<script>"] = 1

    text_stream = io.StringIO()
    Reporter([TextHandler(stream=text_stream, verbose_level=1)]).run([finding], _summary())

    csv_stream = io.StringIO()
    Reporter([CsvHandler(stream=csv_stream)]).run([finding], _summary())

    json_stream = io.StringIO()
    Reporter([JsonHandler(stream=json_stream)]).run([finding], _summary())
    payload = json.loads(json_stream.getvalue())

    html = render_report_html([finding], _summary(), verbose_level=1)

    from sigwood.outputs import pdf as pdf_mod

    rendered: dict[str, str] = {}

    def _fake_pdf_bytes(html_str: str) -> bytes:
        rendered["html"] = html_str
        return b"%PDF-r14"

    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", _fake_pdf_bytes)
    pdf_stream = io.BytesIO()
    Reporter([PdfHandler(stream=pdf_stream, verbose_level=1)]).run([finding], _summary())

    assert "severity_basis: ['resolution-outcome']" in text_stream.getvalue()
    assert "nxdomain_fraction: 0.5" in text_stream.getvalue()
    assert "severity_basis=resolution-outcome" in csv_stream.getvalue()
    assert payload["schema_version"] == 1
    assert payload["findings"][0]["evidence"]["severity_basis"] == ["resolution-outcome"]
    assert payload["findings"][0]["evidence"]["nxdomain_fraction"] == 0.5
    assert "resolution-outcome" in html
    assert rendered["html"] == html
    assert pdf_stream.getvalue() == b"%PDF-r14"

    for human_output in (
        text_stream.getvalue(),
        csv_stream.getvalue(),
        html,
        rendered["html"],
    ):
        assert "\x1b" not in human_output
    assert "<script>" not in html
    assert "<script>" not in rendered["html"]
