"""DNS below-gate group promotion and its full-frame Zeek seam."""

from __future__ import annotations

import ast
import csv
import importlib.util
import io
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from sigwood.common.finding import DetectorContext, RunSummary, Severity
from sigwood.common.output import Reporter
from sigwood.detectors import dns as dns_mod
from sigwood.outputs._render_model import _build_renderable
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs.html import render_report_html
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.pdf import PdfHandler
from sigwood.outputs.text import TextHandler


_NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)
_WINDOW = (_NOW, _NOW)
_LETTERS = (
    "bcdfghjklmnpqrst",
    "cdfghjklmnpqrstv",
    "dfghjklmnpqrstvw",
    "fghjklmnpqrstvwz",
    "ghjklmnpqrstvwzb",
    "hjklmnpqrstvwzbc",
    "jklmnpqrstvwzbcf",
    "klmnpqrstvwzbcfd",
    "lmnpqrstvwzbcfdg",
    "mnpqrstvwzbcfdgh",
)
_HIGH_LABEL = "0123456789bcdfgh"
_GEN_CORPUS_PATH = Path(__file__).resolve().parent.parent / "demo" / "gen_corpus.py"
_GEN_SPEC = importlib.util.spec_from_file_location("gen_corpus_below_gate", _GEN_CORPUS_PATH)
assert _GEN_SPEC is not None and _GEN_SPEC.loader is not None
gen_corpus = importlib.util.module_from_spec(_GEN_SPEC)
_GEN_SPEC.loader.exec_module(gen_corpus)


def _extract(query: str) -> SimpleNamespace:
    parts = query.rstrip(".").split(".")
    return SimpleNamespace(
        domain=parts[-2],
        suffix=parts[-1],
        subdomain=".".join(parts[:-2]),
        top_domain_under_public_suffix=".".join(parts[-2:]),
    )


def _extract_non_psl(query: str) -> SimpleNamespace:
    parts = [label for label in query.rstrip(".").split(".") if label]
    return SimpleNamespace(
        domain=parts[-1] if parts else "",
        suffix="",
        subdomain=".".join(parts[:-1]),
        top_domain_under_public_suffix="",
    )


@pytest.fixture(autouse=True)
def _stable_suffixes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _extract)


def _force_noise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        dns_mod,
        "fit_predict_interruptible",
        lambda matrix, **kwargs: np.full(matrix.shape[0], -1, dtype=int),
    )


def _zeek_rows(
    *,
    parent: str = "family.example",
    subdomains: int = 5,
    total: int = 10,
    nxdomain: int = 9,
) -> list[dict]:
    queries = [f"{label}.{parent}" for label in _LETTERS[:subdomains]]
    return [
        {
            "ts": float(index),
            "src": f"192.0.2.{(index % 4) + 10}",
            "query": queries[index % len(queries)],
            "rcode": 3 if index < nxdomain else 0,
            "rtt": 0.05,
            "ttl": 30.0,
            "answer": [],
            "tc": False,
        }
        for index in range(total)
    ]


def _context(rows: list[dict], **overrides) -> DetectorContext:
    config = {
        "min_cluster_size": 2_000,
        "min_samples": 100,
        "threshold": 1.8,
        "thresh_high_entropy": 1.8,
        "scan_dense_clusters": False,
        **overrides,
    }
    return DetectorContext(
        logs={"dns*.log*": pd.DataFrame(rows)},
        config=config,
        allowlist=None,
        data_window=_WINDOW,
    )


def _promotions(findings) -> list:
    return [
        finding
        for finding in findings
        if finding.evidence.get("tier") == "below_gate_group"
    ]


def _summary(record_count: int = 10) -> RunSummary:
    return RunSummary(
        data_window=_WINDOW,
        record_counts={"dns*.log*": record_count},
        data_size_bytes=100,
        detectors_run=["dns"],
        detectors_skipped={},
    )


@pytest.mark.parametrize(
    ("key", "expected", "example_line"),
    [
        ("promote_below_gate", True, "# promote_below_gate             = true"),
        ("promote_min_subdomains", 5, "# promote_min_subdomains         = 5"),
        (
            "promote_min_nxdomain_fraction",
            0.9,
            "# promote_min_nxdomain_fraction  = 0.9",
        ),
    ],
)
def test_shipped_promotion_defaults_are_mirrored(
    key: str,
    expected: object,
    example_line: str,
) -> None:
    assert dns_mod.DEFAULT_CONFIG[key] == expected
    example = Path("sigwood/data/config_example.toml").read_text(encoding="utf-8")
    assert example_line in example


def test_quiet_family_promotes_at_inclusive_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    rows = _zeek_rows()
    assert all(dns_mod.entropy(label) < 1.8 for label in _LETTERS[:5])

    findings = dns_mod.run(_context(rows))

    promoted = _promotions(findings)
    assert len(promoted) == 1
    finding = promoted[0]
    assert finding.severity == Severity.INFO
    assert finding.title == "family.example"
    assert finding.evidence == {
        "tier": "below_gate_group",
        "source": "zeek",
        "registrable_domain": "family.example",
        "subdomain_count": 5,
        "max_label_score": max(
            round(dns_mod.entropy(label), 4) for label in _LETTERS[:5]
        ),
        "min_label_score": min(
            round(dns_mod.entropy(label), 4) for label in _LETTERS[:5]
        ),
        "total_queries": 10,
        "unique_sources": 4,
        "sample_domains": [f"{label}.family.example" for label in _LETTERS[:5]],
        "querier_ips": [f"192.0.2.{index}" for index in range(10, 14)],
        "nxdomain_fraction": 0.9,
        "nxdomain_count": 9,
        "severity_basis": [],
        "first_seen": "1970-01-01T00:00:00+00:00",
        "last_seen": "1970-01-01T00:00:09+00:00",
        "span_seconds": 9.0,
    }
    assert finding.description == (
        "Registrable domain family.example has a family of names that mostly "
        "fail to resolve. This pattern may resemble automated name generation."
    )
    assert finding.next_steps == [
        "Review the queried names under family.example",
        "Pivot on querier IPs: 192.0.2.10, 192.0.2.11, 192.0.2.12, 192.0.2.13",
        "Check whether the parent is expected in this environment",
    ]
    assert all(step[0].isupper() and not step.endswith(".") for step in finding.next_steps)


def test_fraction_uses_raw_value_before_evidence_rounding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    rows = _zeek_rows(total=20_001, nxdomain=18_000)

    findings = dns_mod.run(_context(rows))

    assert 18_000 / 20_001 < 0.9
    assert round(18_000 / 20_001, 4) == 0.9
    assert _promotions(findings) == []


@pytest.mark.parametrize("include_nan_ts", [False, True])
def test_promotion_missing_event_time_carries_null_evidence(
    monkeypatch: pytest.MonkeyPatch,
    include_nan_ts: bool,
) -> None:
    _force_noise(monkeypatch)
    rows = _zeek_rows()
    for row in rows:
        if include_nan_ts:
            row["ts"] = np.nan
        else:
            row.pop("ts")

    promoted = _promotions(dns_mod.run(_context(rows)))

    assert len(promoted) == 1
    assert promoted[0].evidence["first_seen"] is None
    assert promoted[0].evidence["last_seen"] is None
    assert promoted[0].evidence["span_seconds"] is None


def test_four_subdomains_stay_silent_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    findings = dns_mod.run(_context(_zeek_rows(subdomains=4, total=8, nxdomain=8)))
    assert _promotions(findings) == []


def test_below_fraction_stays_silent_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    findings = dns_mod.run(_context(_zeek_rows(total=10, nxdomain=8)))
    assert _promotions(findings) == []


def test_apex_row_does_not_count_as_a_subdomain_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    rows = _zeek_rows(subdomains=4, total=8, nxdomain=8)
    rows.append({
        "ts": 9.0,
        "src": "192.0.2.20",
        "query": "family.example",
        "rcode": 3,
        "rtt": 0.05,
        "ttl": 30.0,
        "answer": [],
        "tc": False,
    })
    findings = dns_mod.run(_context(rows))
    assert _promotions(findings) == []


def test_resolving_family_stays_silent_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    findings = dns_mod.run(_context(_zeek_rows(nxdomain=0)))
    assert _promotions(findings) == []


def test_default_on_matches_explicit_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    rows = _zeek_rows()

    default = dns_mod.run(_context(rows))
    explicit = dns_mod.run(_context(rows, promote_below_gate=True))

    assert len(_promotions(default)) == 1
    assert _finding_bytes(default) == _finding_bytes(explicit)


def test_false_knob_preserves_frozen_candidate_path_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    rows = [
        *_zeek_rows(),
        {
            "ts": 20.0,
            "src": "192.0.2.20",
            "query": f"{_HIGH_LABEL}.visible.example",
            "rcode": 0,
            "rtt": 0.05,
            "ttl": 30.0,
            "answer": [],
            "tc": False,
        },
    ]
    frame = pd.DataFrame(rows)
    candidate = dns_mod._run_zeek_path(
        frame,
        2_000,
        100,
        thresh_high=1.8,
        scan_cfg={
            "scan_dense_clusters": False,
            "scan_min_high_entropy_fraction": 0.8,
            "scan_min_cluster_members": 100,
            "scan_min_regdomain_share": 0.8,
            "scan_max_members_per_cluster": 500,
        },
    )
    assert candidate is not None
    frozen = dns_mod._shared_back_half(candidate, 1.8, _NOW, _WINDOW)

    disabled = dns_mod.run(_context(rows, promote_below_gate=False))

    assert _finding_bytes(disabled) == _finding_bytes(frozen)


def test_surfaced_above_gate_parent_dedupes_promotion_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    assert dns_mod.entropy(_HIGH_LABEL) >= 1.8
    rows = [
        *_zeek_rows(),
        {
            "ts": 20.0,
            "src": "192.0.2.20",
            "query": f"{_HIGH_LABEL}.family.example",
            "rcode": 3,
            "rtt": 0.05,
            "ttl": 30.0,
            "answer": [],
            "tc": False,
        },
    ]

    findings = dns_mod.run(_context(rows))

    assert len(findings) == 1
    assert findings[0].title == f"{_HIGH_LABEL}.family.example"
    assert _promotions(findings) == []


def _non_psl_promotion_counterfactual(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list, list]:
    """Return absent/present surfaced-parent arms for one private family."""
    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _extract_non_psl)
    queries = [f"{label}.lan" for label in _LETTERS[:5]]
    frame = pd.DataFrame([
        {
            "ts": float(index),
            "src": "192.0.2.10",
            "query": queries[index % len(queries)],
            "rcode": 3,
        }
        for index in range(10)
    ])
    kwargs = {
        "threshold": 1.8,
        "min_subdomains": 5,
        "min_nxdomain_fraction": 0.9,
        "now": _NOW,
        "data_window": _WINDOW,
    }

    absent = dns_mod._make_below_gate_group_findings(
        frame,
        surfaced_parents=set(),
        **kwargs,
    )
    present = dns_mod._make_below_gate_group_findings(
        frame,
        surfaced_parents={"lan"},
        **kwargs,
    )
    return absent, present


def test_non_psl_eligible_family_promotes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An otherwise eligible private family promotes exactly once."""
    absent, _ = _non_psl_promotion_counterfactual(monkeypatch)
    assert len(absent) == 1
    assert absent[0].evidence["registrable_domain"] == "lan"
    assert absent[0].evidence["subdomain_count"] == 5
    assert absent[0].severity == Severity.INFO
    assert absent[0].evidence["severity_basis"] == []
    assert absent[0].description == (
        "Private namespace lan has a family of names that mostly fail to resolve. "
        "Names in a private namespace routinely fail to resolve outside their "
        "local zone."
    )
    assert absent[0].next_steps == [
        "Review the queried names under lan",
        "Pivot on querier IPs: 192.0.2.10",
        "Check whether the parent is expected in this environment",
    ]
    assert not any(
        marker in step
        for step in absent[0].next_steps
        for marker in ("whois", "VirusTotal")
    )


def test_non_psl_surfaced_parent_dedupes_promotion_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same eligible private family is suppressed after its root surfaced."""
    _, present = _non_psl_promotion_counterfactual(monkeypatch)
    assert present == []


def test_unsurfaced_raw_high_name_does_not_dedupe_full_frame_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dns_mod,
        "fit_predict_interruptible",
        lambda matrix, **kwargs: np.zeros(matrix.shape[0], dtype=int),
    )
    rows = [
        *_zeek_rows(),
        {
            "ts": 20.0,
            "src": "192.0.2.20",
            "query": f"{_HIGH_LABEL}.family.example",
            "rcode": 3,
            "rtt": 0.05,
            "ttl": 30.0,
            "answer": [],
            "tc": False,
        },
    ]

    findings = dns_mod.run(_context(rows))

    promoted = _promotions(findings)
    assert len(promoted) == 1
    assert promoted[0].title == "family.example"


def test_zeek_without_rcode_degrades_to_silence_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    rows = _zeek_rows()
    for row in rows:
        row.pop("rcode")

    findings = dns_mod.run(_context(rows))

    assert _promotions(findings) == []


def test_pihole_only_degrades_to_silence_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    rows = [
        {
            "query": f"{label}.family.example",
            "event_type": "query",
            "src": "192.0.2.10",
            "qtype": "A",
        }
        for label in _LETTERS[:5]
    ]
    findings = dns_mod.run(DetectorContext(
        logs={"pihole*.log*": pd.DataFrame(rows)},
        config={
            "threshold": 1.8,
            "pihole": {"min_cluster_size": 2, "min_samples": 1},
        },
        allowlist=None,
        data_window=_WINDOW,
    ))
    assert _promotions(findings) == []


def test_new_tier_is_cap_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    rows = [
        *_zeek_rows(parent="first.example", total=5, nxdomain=5),
        *_zeek_rows(parent="second.example", total=5, nxdomain=5),
    ]
    findings = dns_mod.run(_context(rows))

    renderable = _build_renderable("dns", findings, 0, 1)

    shown = [
        finding
        for section in renderable.sections
        for finding in section.findings
    ]
    assert len(_promotions(findings)) == 2
    assert renderable.cap_truncated == 1
    assert len(shown) == 1
    assert shown[0].evidence["tier"] == "below_gate_group"


def test_nxdomain_measurement_has_one_function_owner_control() -> None:
    tree = ast.parse(Path(dns_mod.__file__).read_text(encoding="utf-8"))
    owners = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_nxdomain_stats"
    ]
    assert len(owners) == 1


def _rng_for(seed: int):
    return lambda channel: random.Random(seed ^ gen_corpus.FLOW[channel])


def _normalized_generator_rows(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame([
        {
            "ts": row["ts"],
            "src": row["id.orig_h"],
            "query": row["query"],
            "rcode": row["rcode"],
            "rtt": row["rtt"],
            "ttl": row["TTLs"],
            "answer": row["answers"],
            "tc": row["TC"],
        }
        for row in rows
    ])


def test_live_generator_quiet_and_loud_arms_share_identity_and_exercise_a1() -> None:
    helper = getattr(gen_corpus, "_gen_below_gate_dns", None)
    assert callable(helper)
    quiet_rows: list[dict] = []
    loud_rows: list[dict] = []

    quiet_parent = helper(
        quiet_rows,
        _rng_for(3759),
        _NOW.timestamp(),
        volume=gen_corpus.BELOW_GATE_QUIET_VOLUME,
    )
    loud_parent = helper(
        loud_rows,
        _rng_for(3759),
        _NOW.timestamp(),
        volume=gen_corpus.BELOW_GATE_LOUD_VOLUME,
    )

    quiet_queries = {row["query"] for row in quiet_rows}
    loud_queries = {row["query"] for row in loud_rows}
    assert quiet_parent == loud_parent
    assert quiet_queries == loud_queries
    assert len(quiet_rows) == gen_corpus.BELOW_GATE_QUIET_VOLUME
    assert len(loud_rows) == gen_corpus.BELOW_GATE_LOUD_VOLUME
    assert len(quiet_queries) == gen_corpus.BELOW_GATE_SUBDOMAIN_COUNT
    assert all(row["rcode"] == 3 for row in [*quiet_rows, *loud_rows])
    assert all(
        dns_mod.entropy(query.split(".", 1)[0]) < 1.8
        for query in quiet_queries
    )

    loud_frame = _normalized_generator_rows(loud_rows)
    candidate = dns_mod._run_zeek_path(
        loud_frame,
        2_000,
        100,
        thresh_high=1.8,
        scan_cfg={
            "scan_dense_clusters": False,
            "scan_min_high_entropy_fraction": 0.8,
            "scan_min_cluster_members": 100,
            "scan_min_regdomain_share": 0.8,
            "scan_max_members_per_cluster": 500,
        },
    )
    assert candidate is None

    findings = dns_mod.run(_context(loud_frame.to_dict("records")))
    promoted = _promotions(findings)
    assert len(promoted) == 1
    assert promoted[0].title == loud_parent
    assert (
        promoted[0].evidence["subdomain_count"]
        == gen_corpus.BELOW_GATE_SUBDOMAIN_COUNT
    )
    assert (
        promoted[0].evidence["total_queries"]
        == gen_corpus.BELOW_GATE_LOUD_VOLUME
    )


def test_default_demo_materializes_only_quiet_arm() -> None:
    helper = getattr(gen_corpus, "_gen_below_gate_dns", None)
    assert callable(helper)
    expected_rows: list[dict] = []
    parent = helper(
        expected_rows,
        _rng_for(3759),
        _NOW.timestamp(),
        volume=gen_corpus.BELOW_GATE_QUIET_VOLUME,
    )
    rows: list[dict] = []
    gen_corpus._gen_dns(rows, _rng_for(3759), _NOW.timestamp())
    family = [row for row in rows if row["query"].endswith(f".{parent}")]
    assert len(family) == gen_corpus.BELOW_GATE_QUIET_VOLUME
    assert {row["query"] for row in family} == {
        row["query"] for row in expected_rows
    }


def test_default_demo_non_psl_family_groups_without_psl_collateral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The seeded private family folds once while the public DGA stays grouped."""
    first: list[dict] = []
    second: list[dict] = []
    apex = gen_corpus._gen_dns(first, _rng_for(3759), _NOW.timestamp())
    apex_repeat = gen_corpus._gen_dns(second, _rng_for(3759), _NOW.timestamp())

    assert apex_repeat == apex
    assert first == second
    private_rows = [row for row in first if row["query"].endswith(".lan")]
    private_queries = {row["query"] for row in private_rows}
    assert len(private_rows) == gen_corpus.NON_PSL_SUBDOMAIN_COUNT
    assert len(private_queries) == gen_corpus.NON_PSL_SUBDOMAIN_COUNT
    private_labels = [query.split(".", 1)[0] for query in private_queries]
    assert all(any(char.isdigit() for char in label) for label in private_labels)
    assert all(dns_mod.entropy(label) >= 1.8 for label in private_labels)

    def _mixed_extract(query: str) -> SimpleNamespace:
        if query.endswith(".lan"):
            return _extract_non_psl(query)
        return _extract(query)

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _mixed_extract)
    _force_noise(monkeypatch)
    frame = _normalized_generator_rows(first)
    findings = dns_mod.run(_context(frame.to_dict("records")))

    private_groups = [
        finding
        for finding in findings
        if finding.evidence.get("registrable_domain") == "lan"
        and "subdomain_count" in finding.evidence
    ]
    assert len(private_groups) == 1
    assert private_groups[0].evidence["subdomain_count"] == len(private_queries)
    assert not any(
        finding.title.endswith(".lan")
        and "subdomain_count" not in finding.evidence
        for finding in findings
    )

    public_groups = [
        finding
        for finding in findings
        if finding.evidence.get("registrable_domain") == apex
        and "subdomain_count" in finding.evidence
    ]
    public_queries = {
        row["query"]
        for row in first
        if row["query"].endswith(f".{apex}")
    }
    expected_public_candidates = sum(
        dns_mod.entropy(query.split(".", 1)[0]) >= 1.8
        for query in public_queries
    )
    assert len(public_groups) == 1
    assert public_groups[0].evidence["subdomain_count"] == expected_public_candidates


def test_promoted_shape_survives_real_sinks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noise(monkeypatch)
    finding = _promotions(dns_mod.run(_context(_zeek_rows())))[0]
    hostile = "=cmd\x1b\x9b\x7f<script>\nsplice.example"
    finding.title = hostile
    finding.evidence["registrable_domain"] = hostile
    finding.evidence["sample_domains"] = [
        hostile,
        "@formula.example",
        "+formula.example",
    ]

    text_stream = io.StringIO()
    Reporter([TextHandler(stream=text_stream, verbose_level=1)]).run(
        [finding],
        _summary(),
    )
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
        return b"%PDF-below-gate"

    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", _fake_pdf_bytes)
    pdf_stream = io.BytesIO()
    Reporter([PdfHandler(stream=pdf_stream, verbose_level=1)]).run(
        [finding],
        _summary(),
    )

    text = text_stream.getvalue()
    csv_text = csv_stream.getvalue()
    csv_row = next(csv.DictReader(io.StringIO(csv_text)))
    json_finding = payload["findings"][0]

    assert payload["schema_version"] == 1
    assert json_finding["title"] == hostile
    assert json_finding["evidence"]["severity_basis"] == []
    assert isinstance(json_finding["evidence"]["sample_domains"], list)
    assert isinstance(json_finding["evidence"]["nxdomain_fraction"], float)
    assert isinstance(json_finding["evidence"]["nxdomain_count"], int)
    assert csv_row["finding"].startswith("'=cmd")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert rendered["html"] == html
    assert pdf_stream.getvalue() == b"%PDF-below-gate"
    for human in (text, csv_text, html, rendered["html"]):
        assert "\x1b" not in human
        assert "\x9b" not in human
        assert "\x7f" not in human


def _finding_bytes(findings) -> bytes:
    payload = [
        {
            "detector": finding.detector,
            "severity": finding.severity.name,
            "title": finding.title,
            "description": finding.description,
            "evidence": finding.evidence,
            "next_steps": finding.next_steps,
            "data_window": [value.isoformat() for value in finding.data_window],
        }
        for finding in findings
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
