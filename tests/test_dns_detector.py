"""Direct tests for the DNS detector - minimal-schema readiness and feature matrix.

All IP addresses use RFC 5737 documentation space: 192.0.2.x, 198.51.100.x.
All domains are placeholders - no real hostnames or infrastructure.
"""

from __future__ import annotations

import random
import socket
from datetime import datetime, timezone
from types import SimpleNamespace

from tests.test_voice_consistency import assert_report_voice

import numpy as np
import pandas as pd
import pytest

from sigwood.common import clustering
from sigwood.common.finding import DetectorContext, Finding, Severity
from sigwood.outputs.text import TextHandler
from sigwood.outputs._render_model import _partition_dns as _dns_sections
from sigwood.detectors.dns import (
    DEFAULT_CONFIG,
    _add_top_suffix_dummies,
    _build_features,
    _build_pihole_aggregate,
    _build_pihole_features,
    _enrich_zeek_with_pihole,
    _query_shape,
    _shared_back_half,
    entropy as dns_entropy,
    run,
)


@pytest.fixture(autouse=True)
def _in_process_clustering(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the in-process escape hatch for every detector-logic test.

    Detector-logic tests in this file do NOT exercise the process-isolation
    machinery - that has its own dedicated suite in
    tests/test_clustering_interruptible.py. Keeping these tests in-process
    avoids spawn overhead per test and keeps the mock target visible to
    the parent process.

    The mock target IS ``sigwood.common.clustering.HDBSCAN`` - NOT
    ``sigwood.detectors.dns.HDBSCAN``: the dns detector does not
    import HDBSCAN, and even if it did, ``fit_predict_interruptible``'s
    in-process path constructs ``clustering.HDBSCAN`` directly. Patching
    the dns-module symbol would intercept nothing.
    """
    monkeypatch.setattr(
        clustering, "_CLUSTERING_ISOLATE_ENABLED", False,
    )

_NOW = datetime(2026, 5, 30, tzinfo=timezone.utc)
_WINDOW = (_NOW, _NOW)


def _ctx(df: pd.DataFrame, cfg: dict | None = None) -> DetectorContext:
    return DetectorContext(
        logs={"dns*.log*": df},
        config=cfg or {},
        allowlist=None,
        data_window=_WINDOW,
    )


def _fake_extract(query: str) -> SimpleNamespace:
    """Stable tldextract stub - avoids cache writes; returns plausible attributes."""
    return SimpleNamespace(
        domain="example",
        suffix="com",
        subdomain="",
        top_domain_under_public_suffix="example.com",
    )


def test_shipped_threshold_matches_high_entropy_bar() -> None:
    """The shipped surface gate stays pinned to the high-entropy bar."""
    assert DEFAULT_CONFIG["threshold"] == DEFAULT_CONFIG["thresh_high_entropy"] == 1.8


def _non_psl_extract(query: str) -> SimpleNamespace:
    """Return the tldextract shape for a private namespace with no suffix."""
    parts = [label for label in query.split(".") if label]
    return SimpleNamespace(
        domain=parts[-1] if parts else "",
        suffix="",
        subdomain=".".join(parts[:-1]),
        top_domain_under_public_suffix="",
    )


def test_non_psl_one_and_two_label_scores_preserve_first_label() -> None:
    """Single-label names and one-child private names keep their prior score."""
    import sigwood.detectors.dns as dns_mod

    for query, scored_label in (("lan", "lan"), ("host1.lan", "host1")):
        score = dns_mod._max_subdomain_entropy(query, _non_psl_extract(query))
        assert score == dns_mod.entropy(scored_label)


def test_non_psl_three_label_score_uses_maximum_subdomain_label() -> None:
    """Every label left of a private root participates in the suspicion score."""
    import sigwood.detectors.dns as dns_mod

    query = "benign.a7f3k9.lan"
    score = dns_mod._max_subdomain_entropy(query, _non_psl_extract(query))

    assert score == max(dns_mod.entropy("benign"), dns_mod.entropy("a7f3k9"))
    assert score > dns_mod.entropy("benign")


# ── Test 1 - minimal-schema run() doesn't raise ───────────────────────────────

def test_run_minimal_schema_does_not_raise(monkeypatch) -> None:
    """dns.run() with only ts/src/query returns a list without raising.

    tldextract is patched to avoid cache writes (PermissionError in sandboxes).
    HDBSCAN config is set small so the test exercises the schema path, not calibration.
    """
    import sigwood.detectors.dns as dns_mod
    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _fake_extract)

    df = pd.DataFrame([
        {"ts": 1.0, "src": "192.0.2.1", "query": "api.test.example.com"},
        {"ts": 2.0, "src": "192.0.2.2", "query": "beacon.test.example.net"},
        {"ts": 3.0, "src": "192.0.2.1", "query": "cdn.example.com"},
        {"ts": 4.0, "src": "192.0.2.3", "query": "dns.test.example.net"},
    ])
    ctx = _ctx(df, cfg={"min_cluster_size": 2, "min_samples": 1})
    result = run(ctx)
    assert isinstance(result, list)


# ── Test 2 - _build_features minimal schema → query-derived only ─────────────

def test_query_shape_uses_dns_labels_not_raw_split_fragments() -> None:
    """Structural DNS features should ignore representation artifacts."""
    normal = _query_shape("api.example.com")
    rooted = _query_shape("api.example.com.")
    malformed = _query_shape(".api..example.com.")
    single = _query_shape("localhost")
    empty = _query_shape("")

    assert rooted == normal
    assert malformed == normal
    assert normal.length == len("api.example.com")
    assert normal.parts == 3
    assert normal.suffix_len == len("com")
    assert normal.domain_len == len("example")
    assert normal.suffix == "com"

    assert single.parts == 1
    assert single.suffix_len == len("localhost")
    assert single.domain_len == 0

    assert empty.length == 0
    assert empty.parts == 0
    assert empty.suffix_len == 0
    assert empty.domain_len == 0
    assert empty.suffix == ""


def test_build_features_minimal_schema_omits_extended_columns() -> None:
    """With only ts/src/query, extended features must be absent (drop-from-matrix, not zero-fill).

    Every suffix in the small batch retains its own identity column.
    """
    df = pd.DataFrame([
        {"ts": 1.0, "src": "192.0.2.1", "query": "api.test.example.com"},
        {"ts": 2.0, "src": "192.0.2.2", "query": "beacon.test.example.net"},
        {"ts": 3.0, "src": "192.0.2.1", "query": "cdn.example.com"},
        {"ts": 4.0, "src": "192.0.2.3", "query": "resolve.test.example.net"},
    ])
    feat = _build_features(df)

    for col in ("qlen", "qparts", "sufflen", "domlen"):
        assert col in feat.columns, f"expected query-derived column {col!r} in feature matrix"

    assert {"TLD_com", "TLD_net"}.issubset(feat.columns)

    for col in ("rtt", "rtt_missing", "ttl", "rcode", "answer", "tc"):
        assert col not in feat.columns, (
            f"{col!r} must be absent from feature matrix when not present in input "
            "(drop-from-matrix, not zero-fill)"
        )


# ── Test 3 - _build_features extended schema → extended features included ─────

def test_build_features_extended_schema_excludes_resolution_outcome() -> None:
    """Extended measurements enter the matrix, but response outcome does not."""
    df = pd.DataFrame([
        {
            "ts": 1.0, "src": "192.0.2.1", "query": "api.example.com",
            "rtt": 0.05, "ttl": 300.0, "rcode": 0,
            "answer": ["198.51.100.1"], "tc": 0,
        },
        {
            "ts": 2.0, "src": "192.0.2.2", "query": "cdn.example.net",
            "rtt": 0.03, "ttl": 60.0, "rcode": 0,
            "answer": ["198.51.100.5", "198.51.100.6"], "tc": 0,
        },
    ])
    feat = _build_features(df)

    for col in ("rtt", "rtt_missing", "ttl", "answer", "tc"):
        assert col in feat.columns, f"expected extended column {col!r} in feature matrix"
    assert "rcode" not in feat.columns


def test_rcode_not_in_zeek_feature_matrix() -> None:
    """Nominal response outcomes remain raw evidence, never clustering geometry."""
    df = pd.DataFrame([
        {
            "ts": float(index),
            "src": f"192.0.2.{index + 1}",
            "query": f"host{index}.example.com",
            "rcode": rcode,
        }
        for index, rcode in enumerate((0, 2, 3, None))
    ])

    feat = _build_features(df)

    assert "rcode" not in feat.columns


def test_suffix_dummies_are_deterministic_and_lossless() -> None:
    """Tied top-20 membership is lexical and no retained identity is dropped."""
    suffixes = pd.Series([f"s{index:02d}" for index in range(21)])

    first = _add_top_suffix_dummies(pd.DataFrame(index=suffixes.index), suffixes)
    permutation = suffixes.sample(frac=1, random_state=3759)
    shuffled = _add_top_suffix_dummies(
        pd.DataFrame(index=permutation.index), permutation,
    ).sort_index()

    expected_columns = {f"TLD_s{index:02d}" for index in range(20)} | {"TLD_other"}
    assert set(first.columns) == expected_columns
    assert set(shuffled.columns) == expected_columns
    pd.testing.assert_frame_equal(first, shuffled)
    assert first.loc[19, "TLD_s19"]
    assert first.loc[20, "TLD_other"]


def test_rtt_missing_is_conditional_and_unscaled() -> None:
    """Rare RTT missingness stays a raw bounded binary feature."""
    rows = [
        {
            "ts": float(index),
            "src": f"192.0.2.{index + 1}",
            "query": f"host{index}.example.com",
            "rtt": None if index == 20 else 0.05,
        }
        for index in range(21)
    ]

    feat = _build_features(pd.DataFrame(rows))
    without_rtt = _build_features(pd.DataFrame([
        {key: value for key, value in row.items() if key != "rtt"}
        for row in rows
    ]))

    assert set(feat["rtt_missing"].unique()) == {0.0, 1.0}
    assert feat.loc[20, "rtt_missing"] == 1.0
    assert "rtt_missing" not in without_rtt.columns


# ── Test 4 - Zeek path golden regression ─────────────────────────────────────

# Fixture: 6 rows - 1 filtered (single-label), 2 cluster-0, 3 noise.
# Noise group: a3f7bc19.malware.example + m8x2q9n.malware.example → malware.example group finding.
# Noise singleton: k8x2m5q7n1p.suspect.example → singleton finding.
#
# R14 adds source="zeek" and severity_basis while preserving the earlier
# evidence values. Assert exact final order and the bounded additive key set.

_REGRESSION_DF = pd.DataFrame([
    {"ts": 1.0, "src": "192.0.2.1", "query": "localhost"},               # single-label → filtered by has_dot
    {"ts": 2.0, "src": "192.0.2.2", "query": "safe.example.com"},        # cluster 0
    {"ts": 3.0, "src": "192.0.2.3", "query": "normal.example.org"},      # cluster 0
    {"ts": 4.0, "src": "192.0.2.1", "query": "a3f7bc19.malware.example"},    # noise → group
    {"ts": 5.0, "src": "192.0.2.2", "query": "m8x2q9n.malware.example"},     # noise → group
    {"ts": 6.0, "src": "192.0.2.1", "query": "k8x2m5q7n1p.suspect.example"}, # noise → singleton
])

# Per-query tldextract results - deterministic, avoids cache writes.
# localhost included so the degenerate filter path is exercised via has_dot.
_REGRESSION_EXT = {
    "localhost":               SimpleNamespace(domain="localhost", suffix="",    subdomain="",            top_domain_under_public_suffix=""),
    "safe.example.com":        SimpleNamespace(domain="example",  suffix="com",  subdomain="safe",         top_domain_under_public_suffix="example.com"),
    "normal.example.org":      SimpleNamespace(domain="example",  suffix="org",  subdomain="normal",       top_domain_under_public_suffix="example.org"),
    "a3f7bc19.malware.example":    SimpleNamespace(domain="malware",  suffix="example",  subdomain="a3f7bc19",     top_domain_under_public_suffix="malware.example"),
    "m8x2q9n.malware.example":     SimpleNamespace(domain="malware",  suffix="example",  subdomain="m8x2q9n",      top_domain_under_public_suffix="malware.example"),
    "k8x2m5q7n1p.suspect.example": SimpleNamespace(domain="suspect",  suffix="example",  subdomain="k8x2m5q7n1p",  top_domain_under_public_suffix="suspect.example"),
}


def _regression_fake_extract(q: str) -> SimpleNamespace:
    return _REGRESSION_EXT.get(
        q,
        SimpleNamespace(domain="", suffix="", subdomain="", top_domain_under_public_suffix=""),
    )


# After degenerate filter, dns_df has 5 rows in this order (localhost dropped):
#   0: safe.example.com, 1: normal.example.org,
#   2: a3f7bc19.malware.example, 3: m8x2q9n.malware.example, 4: k8x2m5q7n1p.suspect.example
# FakeHDBSCAN puts rows 0-1 in cluster 0, rows 2-4 as noise.
class _FakeHDBSCAN:
    def __init__(self, **kwargs): pass
    def fit_predict(self, X: np.ndarray) -> np.ndarray:
        return np.array([0, 0, -1, -1, -1])


def test_zeek_path_regression(monkeypatch) -> None:
    """Golden: Zeek path produces a group + singleton finding in exact order.

    The zeek path adds the frozen R14 severity basis to each finding's evidence.
    Every pre-existing key and value must remain identical.
    """
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _regression_fake_extract)
    monkeypatch.setattr(clustering, "HDBSCAN", _FakeHDBSCAN)

    # Expected entropy values derived from the actual entropy() function -
    # no hardcoded floats; if entropy() changes the test will catch it.
    ent_a3f7bc19 = dns_entropy("a3f7bc19")      # subdomain of a3f7bc19.malware.example
    ent_m8x2q9n  = dns_entropy("m8x2q9n")       # subdomain of m8x2q9n.malware.example
    ent_suspect  = dns_entropy("k8x2m5q7n1p")   # subdomain of k8x2m5q7n1p.suspect.example

    ctx = DetectorContext(
        logs={"dns*.log*": _REGRESSION_DF.copy()},
        config={"min_cluster_size": 5, "min_samples": 1, "threshold": 1.5, "thresh_high_entropy": 1.8},
        allowlist=None,
        data_window=(_NOW, _NOW),
    )
    findings = run(ctx)
    assert_report_voice(findings)

    # ── Exact count ───────────────────────────────────────────────────────────
    assert len(findings) == 2, f"expected 2 findings, got {len(findings)}: {[f.title for f in findings]}"

    # ── Exact order: group first (sorted by max_label_score desc), then singletons ─
    golden_titles = [
        "malware.example",
        "k8x2m5q7n1p.suspect.example",
    ]
    assert [f.title for f in findings] == golden_titles, (
        f"finding order mismatch: {[f.title for f in findings]}"
    )

    # ── Group finding ─────────────────────────────────────────────────────────
    grp_f = findings[0]
    # max_ent < 1.8 so MEDIUM (subdomains score 1.77 and 1.70)
    assert grp_f.severity == Severity.MEDIUM

    expected_grp_ev = {
        "registrable_domain": "malware.example",
        "subdomain_count": 2,
        "max_label_score": round(max(ent_a3f7bc19, ent_m8x2q9n), 4),
        "min_label_score": round(min(ent_a3f7bc19, ent_m8x2q9n), 4),
        "total_queries": 2,
        "unique_sources": 2,
        "sample_domains": ["a3f7bc19.malware.example", "m8x2q9n.malware.example"],
        "querier_ips": ["192.0.2.1", "192.0.2.2"],
    }
    for key, expected_val in expected_grp_ev.items():
        assert grp_f.evidence[key] == expected_val, (
            f"group evidence[{key!r}]: got {grp_f.evidence[key]!r}, expected {expected_val!r}"
        )

    # R14 adds source plus the explicit, empty basis for an uncorroborated group.
    assert grp_f.evidence.get("source") == "zeek", (
        f"expected source='zeek', got {grp_f.evidence.get('source')!r}"
    )
    _pre_refactor_grp_keys = {
        "registrable_domain", "subdomain_count", "max_label_score", "min_label_score",
        "total_queries", "unique_sources", "sample_domains", "querier_ips",
    }
    new_grp_keys = set(grp_f.evidence.keys()) - _pre_refactor_grp_keys
    assert new_grp_keys == {
        "source",
        "severity_basis",
        "first_seen",
        "last_seen",
        "span_seconds",
    }, (
        f"unexpected additive group evidence keys: {new_grp_keys}"
    )
    assert grp_f.evidence["severity_basis"] == []
    assert grp_f.evidence["first_seen"] == "1970-01-01T00:00:04+00:00"
    assert grp_f.evidence["last_seen"] == "1970-01-01T00:00:05+00:00"
    assert grp_f.evidence["span_seconds"] == 1.0

    # ── Singleton finding ─────────────────────────────────────────────────────
    sng_f = findings[1]
    assert sng_f.severity == Severity.MEDIUM
    assert sng_f.title == "k8x2m5q7n1p.suspect.example"

    expected_sng_ev = {
        "label_score": round(ent_suspect, 4),
        "query_count": 1,
        "unique_sources": 1,
        "querier_ips": ["192.0.2.1"],
        "rcode_distribution": {},            # no rcode column in fixture
    }
    for key, expected_val in expected_sng_ev.items():
        assert sng_f.evidence[key] == expected_val, (
            f"singleton evidence[{key!r}]: got {sng_f.evidence[key]!r}, expected {expected_val!r}"
        )
    assert sng_f.evidence.get("source") == "zeek", (
        f"expected source='zeek', got {sng_f.evidence.get('source')!r}"
    )
    _pre_refactor_sng_keys = {
        "label_score", "query_count", "unique_sources", "querier_ips", "rcode_distribution",
    }
    new_sng_keys = set(sng_f.evidence.keys()) - _pre_refactor_sng_keys
    assert new_sng_keys == {
        "source",
        "severity_basis",
        "first_seen",
        "last_seen",
        "span_seconds",
    }, (
        f"unexpected additive singleton evidence keys: {new_sng_keys}"
    )
    assert sng_f.evidence["severity_basis"] == []
    assert sng_f.evidence["first_seen"] == "1970-01-01T00:00:06+00:00"
    assert sng_f.evidence["last_seen"] == "1970-01-01T00:00:06+00:00"
    assert sng_f.evidence["span_seconds"] == 0.0


# ── Pihole aggregate tests ────────────────────────────────────────────────────

def test_pihole_aggregate_produces_per_domain_rows(monkeypatch) -> None:
    """_build_pihole_aggregate produces exactly one row per unique query domain."""
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", lambda q: SimpleNamespace(
        domain="example", suffix="com", subdomain=q.split(".")[0],
        top_domain_under_public_suffix="example.com",
    ))

    rows = [
        # alpha - 3 query events from 2 clients + 1 forwarded
        {"query": "alpha.example.com", "event_type": "query",     "src": "192.0.2.1", "qtype": "A"},
        {"query": "alpha.example.com", "event_type": "query",     "src": "192.0.2.1", "qtype": "A"},
        {"query": "alpha.example.com", "event_type": "query",     "src": "192.0.2.2", "qtype": "A"},
        {"query": "alpha.example.com", "event_type": "forwarded", "src": None,        "qtype": None},
        # beta - 2 query events from 1 client
        {"query": "beta.example.com",  "event_type": "query",     "src": "192.0.2.3", "qtype": "AAAA"},
        {"query": "beta.example.com",  "event_type": "query",     "src": "192.0.2.3", "qtype": "AAAA"},
        # gamma - 4 query events from 3 clients
        {"query": "gamma.example.com", "event_type": "query",     "src": "192.0.2.1", "qtype": "A"},
        {"query": "gamma.example.com", "event_type": "query",     "src": "192.0.2.4", "qtype": "A"},
        {"query": "gamma.example.com", "event_type": "query",     "src": "192.0.2.5", "qtype": "A"},
        {"query": "gamma.example.com", "event_type": "query",     "src": "192.0.2.5", "qtype": "A"},
    ]
    agg = _build_pihole_aggregate(pd.DataFrame(rows))

    assert len(agg) == 3, f"expected 3 rows, got {len(agg)}"

    alpha = agg[agg["query"] == "alpha.example.com"].iloc[0]
    assert alpha["query_count"] == 3
    assert alpha["unique_clients"] == 2
    # 1 forwarded / 3 query events
    assert round(float(alpha["forward_ratio"]), 4) == round(1 / 3, 4)
    assert pd.isna(alpha["first_ts"])
    assert pd.isna(alpha["last_ts"])

    beta = agg[agg["query"] == "beta.example.com"].iloc[0]
    assert beta["query_count"] == 2
    assert beta["unique_clients"] == 1

    gamma = agg[agg["query"] == "gamma.example.com"].iloc[0]
    assert gamma["query_count"] == 4
    assert gamma["unique_clients"] == 3


def test_pihole_blocked_domain_evidence(monkeypatch) -> None:
    """A domain with a gravity_blocked event produces was_blocked=True, block_ratio > 0."""
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", lambda q: SimpleNamespace(
        domain="example", suffix="com", subdomain="blocked",
        top_domain_under_public_suffix="example.com",
    ))

    rows = [
        {"query": "blocked.example.com", "event_type": "query",           "src": "192.0.2.1", "qtype": "A"},
        {"query": "blocked.example.com", "event_type": "query",           "src": "192.0.2.1", "qtype": "A"},
        {"query": "blocked.example.com", "event_type": "gravity_blocked", "src": None,        "qtype": None},
    ]
    agg = _build_pihole_aggregate(pd.DataFrame(rows))

    assert len(agg) == 1
    row = agg.iloc[0]
    assert bool(row["was_blocked"]) is True
    assert row["block_ratio"] > 0
    # block_count=1, total_count=3, block_ratio=1/3
    assert round(float(row["block_ratio"]), 4) == round(1 / 3, 4)


def test_block_ratio_union_gravity_and_regex(monkeypatch) -> None:
    """block_count collapses gravity_blocked + regex_blocked (not counted separately)."""
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", lambda q: SimpleNamespace(
        domain="example", suffix="com", subdomain="evil",
        top_domain_under_public_suffix="example.com",
    ))

    rows = [
        {"query": "evil.example.com", "event_type": "query",           "src": "192.0.2.1", "qtype": "A"},
        {"query": "evil.example.com", "event_type": "query",           "src": "192.0.2.1", "qtype": "A"},
        {"query": "evil.example.com", "event_type": "gravity_blocked", "src": None,        "qtype": None},
        {"query": "evil.example.com", "event_type": "gravity_blocked", "src": None,        "qtype": None},
        {"query": "evil.example.com", "event_type": "regex_blocked",   "src": None,        "qtype": None},
    ]
    agg = _build_pihole_aggregate(pd.DataFrame(rows))

    assert len(agg) == 1
    row = agg.iloc[0]
    assert int(row["block_count"]) == 3, "gravity_blocked (2) + regex_blocked (1) must sum to 3"
    # total_count=5, block_ratio=3/5=0.6
    assert round(float(row["block_ratio"]), 4) == round(3 / 5, 4)


def test_block_ratio_not_in_pihole_feature_matrix() -> None:
    """Evidence-only columns must not appear in the pihole feature matrix."""
    agg_df = pd.DataFrame([
        {
            "query": "sub1.example.com",
            "query_count": 5, "forward_count": 2, "cache_count": 1,
            "block_count": 0, "special_count": 0, "total_count": 8,
            "unique_clients": 2, "unique_qtypes": 1,
            "querier_ips": ["192.0.2.1", "192.0.2.2"],
            "qtype_counts": {"A": 5},
            "forward_ratio": 0.4, "cache_ratio": 0.2,
            "block_ratio": 0.0, "was_blocked": False,
            "unique_sources": 2,
            "first_ts": 1.0, "last_ts": 5.0,
        },
        {
            "query": "sub2.example.net",
            "query_count": 3, "forward_count": 1, "cache_count": 0,
            "block_count": 1, "special_count": 0, "total_count": 4,
            "unique_clients": 1, "unique_qtypes": 2,
            "querier_ips": ["192.0.2.3"],
            "qtype_counts": {"A": 2, "AAAA": 1},
            "forward_ratio": 0.333, "cache_ratio": 0.0,
            "block_ratio": 0.25, "was_blocked": True,
            "unique_sources": 1,
            "first_ts": 2.0, "last_ts": 8.0,
        },
    ])

    feat = _build_pihole_features(agg_df)

    assert set(feat.columns) == {
        "q_len",
        "q_parts",
        "q_suffix_len",
        "q_domain_len",
        "log1p_query_count",
        "log1p_unique_clients",
        "unique_qtypes",
        "log1p_forward_ratio",
        "log1p_cache_ratio",
        "TLD_com",
        "TLD_net",
    }
    for col in ("block_ratio", "was_blocked", "block_count", "forward_count",
                "cache_count", "total_count", "special_count",
                "first_ts", "last_ts", "rtt_missing"):
        assert col not in feat.columns, f"{col!r} must not appear in pihole feature matrix"


# ── Both-mode (Zeek + pihole) tests ──────────────────────────────────────────

# Shared fixture for both-mode tests.
# After degenerate filter, dns_df has 3 rows: safe→cluster 0, normal→cluster 0, noise.
# FakeHDBSCAN3 assigns [0, 0, -1] so a3f7bc19.example.com is the noise domain.
_BOTH_MODE_ZEEK_EXT = {
    "safe.example.com":     SimpleNamespace(domain="example", suffix="com", subdomain="safe",     top_domain_under_public_suffix="example.com"),
    "normal.example.net":   SimpleNamespace(domain="example", suffix="net", subdomain="normal",   top_domain_under_public_suffix="example.net"),
    "a3f7bc19.example.com": SimpleNamespace(domain="example", suffix="com", subdomain="a3f7bc19", top_domain_under_public_suffix="example.com"),
}

_BOTH_MODE_ZEEK_DF = pd.DataFrame([
    {"ts": 1.0, "src": "192.0.2.1", "query": "safe.example.com"},
    {"ts": 2.0, "src": "192.0.2.2", "query": "normal.example.net"},
    {"ts": 3.0, "src": "192.0.2.1", "query": "a3f7bc19.example.com"},
])

_BOTH_MODE_PIHOLE_DF = pd.DataFrame([
    {"ts": 4.0, "src": None,        "query": "a3f7bc19.example.com", "event_type": "gravity_blocked", "qtype": None},
    {"ts": 5.0, "src": "192.0.2.1", "query": "a3f7bc19.example.com", "event_type": "query",           "qtype": "A"},
])


class _FakeHDBSCAN3:
    def __init__(self, **kwargs): pass
    def fit_predict(self, X: np.ndarray) -> np.ndarray:
        return np.array([0, 0, -1])


def test_both_mode_zeek_enriched_with_pihole_block(monkeypatch) -> None:
    """Both-mode: Zeek noise domain enriched with pihole block data carries was_blocked in evidence."""
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", lambda q: _BOTH_MODE_ZEEK_EXT.get(
        q, SimpleNamespace(domain="", suffix="", subdomain="", top_domain_under_public_suffix=""),
    ))
    monkeypatch.setattr(clustering, "HDBSCAN", _FakeHDBSCAN3)

    ctx = DetectorContext(
        logs={"dns*.log*": _BOTH_MODE_ZEEK_DF.copy(), "pihole*.log*": _BOTH_MODE_PIHOLE_DF.copy()},
        config={"min_cluster_size": 3, "min_samples": 1, "threshold": 1.5, "thresh_high_entropy": 1.8},
        allowlist=None,
        data_window=_WINDOW,
    )
    findings = run(ctx)

    assert len(findings) >= 1, "expected at least one finding from both-mode run"
    f = findings[0]
    assert f.evidence["source"] == "zeek"
    assert f.evidence.get("was_blocked") is True, "noise domain blocked by pihole must carry was_blocked=True"
    assert f.evidence.get("block_ratio", 0.0) > 0.0, "block_ratio must be > 0 for a blocked domain"


def test_both_mode_pihole_not_independently_clustered(monkeypatch) -> None:
    """Both-mode: pihole data enriches Zeek; no independent pihole clustering happens."""
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", lambda q: _BOTH_MODE_ZEEK_EXT.get(
        q, SimpleNamespace(domain="", suffix="", subdomain="", top_domain_under_public_suffix=""),
    ))
    monkeypatch.setattr(clustering, "HDBSCAN", _FakeHDBSCAN3)

    ctx = DetectorContext(
        logs={"dns*.log*": _BOTH_MODE_ZEEK_DF.copy(), "pihole*.log*": _BOTH_MODE_PIHOLE_DF.copy()},
        config={"min_cluster_size": 3, "min_samples": 1, "threshold": 1.5, "thresh_high_entropy": 1.8},
        allowlist=None,
        data_window=_WINDOW,
    )
    findings = run(ctx)

    assert all(f.evidence.get("source") != "pihole" for f in findings), (
        "both-mode must only produce zeek findings - no independent pihole clustering"
    )


# ── Pihole event-type exclusion tests ────────────────────────────────────────

def test_excluded_event_types_not_in_aggregation(monkeypatch) -> None:
    """dnssec_query, dhcp, and pihole_hostname must not contribute to query_count."""
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", lambda q: SimpleNamespace(
        domain="example", suffix="com", subdomain="target",
        top_domain_under_public_suffix="example.com",
    ))

    rows = [
        # 3 query events that SHOULD count
        {"query": "target.example.com", "event_type": "query",           "src": "192.0.2.1", "qtype": "A"},
        {"query": "target.example.com", "event_type": "query",           "src": "192.0.2.1", "qtype": "A"},
        {"query": "target.example.com", "event_type": "query",           "src": "192.0.2.2", "qtype": "A"},
        # excluded event types
        {"query": "target.example.com", "event_type": "dnssec_query",    "src": None, "qtype": "DS"},
        {"query": "target.example.com", "event_type": "dnssec_query",    "src": None, "qtype": "DNSKEY"},
        {"query": "target.example.com", "event_type": "dhcp",            "src": None, "qtype": None},
        {"query": "target.example.com", "event_type": "pihole_hostname", "src": None, "qtype": None},
    ]
    agg = _build_pihole_aggregate(pd.DataFrame(rows))

    assert len(agg) == 1
    assert agg.iloc[0]["query_count"] == 3, "only query events should count in query_count"


def test_special_not_in_cluster_features_but_in_evidence(monkeypatch) -> None:
    """special events count as annotation in aggregate but must not enter the feature matrix."""
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", lambda q: SimpleNamespace(
        domain="example", suffix="com", subdomain="relay",
        top_domain_under_public_suffix="example.com",
    ))

    rows = [
        {"query": "relay.example.com", "event_type": "query",   "src": "192.0.2.1", "qtype": "A"},
        {"query": "relay.example.com", "event_type": "query",   "src": "192.0.2.1", "qtype": "A"},
        {"query": "relay.example.com", "event_type": "query",   "src": "192.0.2.2", "qtype": "A"},
        {"query": "relay.example.com", "event_type": "special", "src": None,        "qtype": None},
        {"query": "relay.example.com", "event_type": "special", "src": None,        "qtype": None},
    ]
    agg = _build_pihole_aggregate(pd.DataFrame(rows))

    assert len(agg) == 1
    assert int(agg.iloc[0]["special_count"]) == 2, "special events must be counted in aggregate"

    feat = _build_pihole_features(agg)
    assert "special_count" not in feat.columns, "special_count must not enter the feature matrix"


# ── Pihole-only end-to-end test ───────────────────────────────────────────────

_PIHOLE_ONLY_EXT = {
    "a3f7bc19.sus1.example":    SimpleNamespace(domain="sus1", suffix="example", subdomain="a3f7bc19",    top_domain_under_public_suffix="sus1.example"),
    "m8x2q9n.sus2.example":     SimpleNamespace(domain="sus2", suffix="example", subdomain="m8x2q9n",     top_domain_under_public_suffix="sus2.example"),
    "k8x2m5q7n1p.sus3.example": SimpleNamespace(domain="sus3", suffix="example", subdomain="k8x2m5q7n1p", top_domain_under_public_suffix="sus3.example"),
}


def test_pihole_only_run_produces_findings(monkeypatch) -> None:
    """pihole-only run returns findings with source='pihole' for all entries."""
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", lambda q: _PIHOLE_ONLY_EXT.get(
        q, SimpleNamespace(domain="", suffix="", subdomain="", top_domain_under_public_suffix=""),
    ))

    class _FakeAllNoise:
        def __init__(self, **kwargs): pass
        def fit_predict(self, X: np.ndarray) -> np.ndarray:
            return np.full(len(X), -1, dtype=int)

    monkeypatch.setattr(clustering, "HDBSCAN", _FakeAllNoise)

    rows = []
    for domain_index, domain in enumerate(_PIHOLE_ONLY_EXT):
        for i in range(3):
            rows.append({
                "ts": float(domain_index * 10 + i),
                "query": domain,
                "event_type": "query",
                "src": f"192.0.2.{i + 1}",
                "qtype": "A",
            })
    pihole_df = pd.DataFrame(rows)

    ctx = DetectorContext(
        logs={"pihole*.log*": pihole_df},
        config={
            "threshold": 1.5,
            "thresh_high_entropy": 1.8,
            "pihole": {"min_cluster_size": 2, "min_samples": 1},
        },
        allowlist=None,
        data_window=_WINDOW,
    )
    findings = run(ctx)

    assert isinstance(findings, list)
    assert len(findings) >= 1, "pihole-only run should produce at least one finding"
    assert all(f.evidence.get("source") == "pihole" for f in findings), (
        "all findings from a pihole-only run must carry source='pihole'"
    )
    assert all(f.severity == Severity.MEDIUM for f in findings)
    assert all(f.evidence["severity_basis"] == [] for f in findings)
    first = next(
        finding
        for finding in findings
        if finding.title == "a3f7bc19.sus1.example"
    )
    assert first.evidence["first_seen"] == "1970-01-01T00:00:00+00:00"
    assert first.evidence["last_seen"] == "1970-01-01T00:00:02+00:00"
    assert first.evidence["span_seconds"] == 2.0


def test_non_psl_candidates_share_one_grouping_key_on_both_paths(
    monkeypatch,
) -> None:
    """Zeek and Pi-hole candidates converge on one private-namespace family."""
    import sigwood.detectors.dns as dns_mod

    queries = [f"{label}.lan" for label in _high_entropy_labels(5)]
    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _non_psl_extract)
    monkeypatch.setattr(
        dns_mod,
        "fit_predict_interruptible",
        lambda matrix, **kwargs: np.full(matrix.shape[0], -1, dtype=int),
    )
    scan_cfg = {
        key: DEFAULT_CONFIG[key]
        for key in (
            "scan_dense_clusters",
            "scan_min_high_entropy_fraction",
            "scan_min_cluster_members",
            "scan_min_regdomain_share",
            "scan_max_members_per_cluster",
        )
    }
    scan_cfg["scan_dense_clusters"] = False

    zeek = dns_mod._run_zeek_path(
        pd.DataFrame([
            {
                "ts": float(index),
                "src": "192.0.2.10",
                "query": query,
                "rcode": 3,
            }
            for index, query in enumerate(queries)
        ]),
        2,
        1,
        thresh_high=1.8,
        scan_cfg=scan_cfg,
    )
    pihole = dns_mod._run_pihole_path(
        pd.DataFrame([
            {
                "query": query,
                "event_type": "query",
                "src": "192.0.2.10",
                "qtype": "A",
            }
            for query in queries
        ]),
        {"min_cluster_size": 2, "min_samples": 1},
    )

    assert zeek is not None and set(zeek["registrable_domain"]) == {"lan"}
    assert pihole is not None and set(pihole["registrable_domain"]) == {"lan"}
    findings = dns_mod._shared_back_half(zeek, 1.8, _NOW, _WINDOW)
    groups = [finding for finding in findings if "subdomain_count" in finding.evidence]
    assert len(groups) == 1
    assert groups[0].evidence["registrable_domain"] == "lan"
    assert groups[0].evidence["subdomain_count"] == len(queries)


# ── _shared_back_half grouping ────────────────────────────────────────────────

def _resolution_group_candidates(
    registrable_domain: str,
    *,
    has_public_suffix: bool,
) -> pd.DataFrame:
    """Two one-failure members with identical behavior and suffix provenance."""
    labels = _high_entropy_labels(2)
    return pd.DataFrame([
        {
            "query": f"{label}.{registrable_domain}",
            "label_entropy": dns_entropy(label),
            "registrable_domain": registrable_domain,
            "has_public_suffix": has_public_suffix,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.10"],
            "source": "zeek",
            "query_count": 1,
            "rcode_distribution": {3: 1},
        }
        for label in labels
    ])


def test_non_psl_group_keeps_nxdomain_measurement_without_corroboration() -> None:
    """Private-namespace NXDOMAIN is measured but does not raise severity."""
    findings = _shared_back_half(
        _resolution_group_candidates("lan", has_public_suffix=False),
        threshold=1.8,
        now=_NOW,
        data_window=_WINDOW,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["severity_basis"] == []
    assert finding.evidence["nxdomain_fraction"] == 1.0
    assert finding.evidence["nxdomain_count"] == 2
    assert finding.description == (
        "Private namespace lan has 2 subdomains in the DNS noise cluster with "
        "elevated label scores. The label score is the only signal - nothing in "
        "the query behavior corroborates it."
    )
    assert finding.next_steps == [
        "Check the local DNS zone or resolver that serves lan",
        "Confirm these names are expected on the internal network",
        "Check conn.log for connections to IPs resolved from these queries",
        "Pivot on querier IPs: 192.0.2.10",
    ]
    assert not any(
        marker in step
        for step in finding.next_steps
        for marker in ("whois", "VirusTotal")
    )


def test_psl_group_with_same_nxdomain_shape_stays_high_control() -> None:
    """The identical public-suffix group keeps resolution corroboration."""
    findings = _shared_back_half(
        _resolution_group_candidates(
            "family.example",
            has_public_suffix=True,
        ),
        threshold=1.8,
        now=_NOW,
        data_window=_WINDOW,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.evidence["severity_basis"] == ["resolution-outcome"]
    assert finding.evidence["nxdomain_fraction"] == 1.0
    assert finding.evidence["nxdomain_count"] == 2
    assert finding.description == (
        "Registrable domain family.example has 2 subdomains in the DNS noise "
        "cluster with elevated label scores. 2 lookups under this name failed "
        "to resolve (100% of the total)."
    )
    assert finding.next_steps == [
        "Check domain registration: whois family.example",
        "Look up family.example on VirusTotal and Shodan",
        "Check conn.log for connections to IPs resolved from these queries",
        "Pivot on querier IPs: 192.0.2.10",
    ]


def test_shared_back_half_grouping_consistency() -> None:
    """Two candidate rows sharing the same registrable domain produce one group finding."""
    candidate_df = pd.DataFrame([
        {
            "query": "a3f7bc19.example.com",
            "label_entropy": 1.77,
            "registrable_domain": "example.com",
            "has_public_suffix": True,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.1"],
            "source": "pihole",
            "query_count": 5,
            "was_blocked": False,
            "block_ratio": 0.0,
            "cache_ratio": 0.2,
            "forward_ratio": 0.8,
            "qtype_counts": {"A": 5},
            "special_count": 0,
        },
        {
            "query": "m8x2q9n.example.com",
            "label_entropy": 1.70,
            "registrable_domain": "example.com",
            "has_public_suffix": True,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.2"],
            "source": "pihole",
            "query_count": 3,
            "was_blocked": False,
            "block_ratio": 0.0,
            "cache_ratio": 0.3,
            "forward_ratio": 0.7,
            "qtype_counts": {"A": 3},
            "special_count": 0,
        },
    ])

    findings = _shared_back_half(candidate_df, threshold=1.5, now=_NOW, data_window=_WINDOW)

    assert len(findings) == 1, "two rows with same registrable domain must produce one group finding"
    assert findings[0].evidence["subdomain_count"] == 2
    assert findings[0].evidence["source"] == "pihole"
    assert findings[0].evidence["severity_basis"] == []
    assert findings[0].severity == Severity.MEDIUM


def test_dns_group_event_time_spans_all_members() -> None:
    """A group's event-time evidence uses the earliest and latest member."""
    candidate_df = pd.DataFrame([
        {
            "query": "a3f7bc19.family.example",
            "label_entropy": 2.1,
            "registrable_domain": "family.example",
            "has_public_suffix": True,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.10"],
            "source": "zeek",
            "query_count": 2,
            "rcode_distribution": {},
            "first_ts": 10.0,
            "last_ts": 12.0,
        },
        {
            "query": "m8x2q9n.family.example",
            "label_entropy": 2.0,
            "registrable_domain": "family.example",
            "has_public_suffix": True,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.11"],
            "source": "zeek",
            "query_count": 3,
            "rcode_distribution": {},
            "first_ts": 20.0,
            "last_ts": 30.0,
        },
    ])

    findings = _shared_back_half(
        candidate_df,
        threshold=1.8,
        now=_NOW,
        data_window=_WINDOW,
    )

    assert len(findings) == 1
    assert findings[0].evidence["first_seen"] == "1970-01-01T00:00:10+00:00"
    assert findings[0].evidence["last_seen"] == "1970-01-01T00:00:30+00:00"
    assert findings[0].evidence["span_seconds"] == 20.0


def test_pihole_group_qtype_counts_aggregated() -> None:
    """pihole group finding aggregates qtype_counts across all member rows."""
    candidate_df = pd.DataFrame([
        {
            "query": "a3f7bc19.example.com",
            "label_entropy": 1.77,
            "registrable_domain": "example.com",
            "has_public_suffix": True,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.1"],
            "source": "pihole",
            "query_count": 5,
            "was_blocked": False,
            "block_ratio": 0.0,
            "cache_ratio": 0.2,
            "forward_ratio": 0.8,
            "qtype_counts": {"A": 4, "AAAA": 1},
            "special_count": 0,
        },
        {
            "query": "m8x2q9n.example.com",
            "label_entropy": 1.70,
            "registrable_domain": "example.com",
            "has_public_suffix": True,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.2"],
            "source": "pihole",
            "query_count": 3,
            "was_blocked": False,
            "block_ratio": 0.0,
            "cache_ratio": 0.3,
            "forward_ratio": 0.7,
            "qtype_counts": {"A": 2, "HTTPS": 1},
            "special_count": 0,
        },
    ])

    findings = _shared_back_half(candidate_df, threshold=1.5, now=_NOW, data_window=_WINDOW)

    assert len(findings) == 1
    qtypes = findings[0].evidence.get("qtype_counts")
    assert isinstance(qtypes, dict), "group finding must have qtype_counts dict"
    assert qtypes.get("A") == 6, f"A count should be 4+2=6, got {qtypes.get('A')}"
    assert qtypes.get("AAAA") == 1, f"AAAA count should be 1, got {qtypes.get('AAAA')}"
    assert qtypes.get("HTTPS") == 1, f"HTTPS count should be 1, got {qtypes.get('HTTPS')}"


# ── Null/invalid query guard ──────────────────────────────────────────────────

def test_pihole_aggregate_null_query_rows_ignored(monkeypatch) -> None:
    """Rows with query=None, query='', or query=<non-string> are silently dropped."""
    import sigwood.detectors.dns as dns_mod

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", lambda q: SimpleNamespace(
        domain="example", suffix="com", subdomain="api",
        top_domain_under_public_suffix="example.com",
    ))

    rows = [
        {"query": "api.example.com", "event_type": "query", "src": "192.0.2.1", "qtype": "A"},
        {"query": None,               "event_type": "query", "src": "192.0.2.1", "qtype": "A"},
        {"query": "",                 "event_type": "query", "src": "192.0.2.1", "qtype": "A"},
        {"query": 123,                "event_type": "query", "src": "192.0.2.1", "qtype": "A"},
    ]
    agg = _build_pihole_aggregate(pd.DataFrame(rows))

    assert len(agg) == 1, f"expected 1 valid row, got {len(agg)}"
    assert agg.iloc[0]["query"] == "api.example.com"


# ── Partial pihole config override ───────────────────────────────────────────

def test_pihole_cfg_partial_override_keeps_defaults(monkeypatch) -> None:
    """Partial pihole config override preserves unspecified defaults."""
    import sigwood.detectors.dns as dns_mod

    captured: dict = {}

    def _spy_run_pihole_path(pihole_df: pd.DataFrame, pihole_cfg: dict) -> None:
        captured["pihole_cfg"] = dict(pihole_cfg)
        return None

    monkeypatch.setattr(dns_mod, "_run_pihole_path", _spy_run_pihole_path)

    pihole_df = pd.DataFrame([
        {"ts": 1.0, "src": "192.0.2.1", "query": "api.example.com", "event_type": "query", "qtype": "A"},
    ])
    ctx = DetectorContext(
        logs={"pihole*.log*": pihole_df},
        config={"pihole": {"min_samples": 3}},
        allowlist=None,
        data_window=_WINDOW,
    )
    run(ctx)

    assert "pihole_cfg" in captured, "_run_pihole_path was not called"
    assert captured["pihole_cfg"]["min_cluster_size"] == DEFAULT_CONFIG["pihole"]["min_cluster_size"], (
        "min_cluster_size must fall back to DEFAULT_CONFIG when not overridden"
    )
    assert captured["pihole_cfg"]["min_samples"] == 3, "min_samples must be taken from user config"


# ── _enrich_zeek_with_pihole: no-match defaults ───────────────────────────────

def test_both_mode_no_pihole_match_block_ratio_is_zero() -> None:
    """Zeek domains with no pihole match get block_ratio=0.0, was_blocked=False (never NaN)."""
    dns_df = pd.DataFrame([
        {"ts": 1.0, "src": "192.0.2.1", "query": "sub.example.com"},
        {"ts": 2.0, "src": "192.0.2.2", "query": "api.example.com"},
    ])
    pihole_df = pd.DataFrame([
        {"ts": 3.0, "src": None, "query": "other.unrelated.example", "event_type": "gravity_blocked", "qtype": None},
    ])

    result = _enrich_zeek_with_pihole(dns_df.copy(), pihole_df)

    assert "block_ratio" in result.columns
    assert "was_blocked" in result.columns
    assert (result["block_ratio"] == 0.0).all(), "unmatched domains must have block_ratio=0.0"
    assert (result["was_blocked"] == False).all(), "unmatched domains must have was_blocked=False"
    assert not result["block_ratio"].isna().any(), "block_ratio must never be NaN"


# ── Text renderer tests ───────────────────────────────────────────────────────

def _make_dns_finding(severity: Severity, title: str, evidence: dict) -> Finding:
    return Finding(
        detector="dns",
        severity=severity,
        title=title,
        description="test description",
        evidence=evidence,
        next_steps=[],
        ts_generated=_NOW,
        data_window=_WINDOW,
    )


def test_text_renderer_pihole_default_shows_blocked() -> None:
    """Pihole singleton with was_blocked=True shows BLOCKED token in default output."""
    f = _make_dns_finding(
        Severity.HIGH,
        "a3f7bc19.example.com",
        {
            "source": "pihole",
            "label_score": 1.77,
            "query_count": 5,
            "unique_sources": 2,
            "querier_ips": ["192.0.2.1"],
            "was_blocked": True,
            "block_ratio": 0.5,
            "cache_ratio": 0.2,
            "forward_ratio": 0.3,
            "qtype_counts": {"A": 5},
            "special_count": 0,
        },
    )
    handler = TextHandler(verbose_level=0)
    lines = handler._render_dns_group(_dns_sections([f]))
    output = "\n".join(lines)
    assert "BLOCKED" in output, "was_blocked=True must show BLOCKED token in default output"


def test_text_renderer_pihole_default_no_blocked_marker() -> None:
    """Pihole singleton with was_blocked=False omits BLOCKED token from default output."""
    f = _make_dns_finding(
        Severity.MEDIUM,
        "sub.example.com",
        {
            "source": "pihole",
            "label_score": 1.55,
            "query_count": 3,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.1"],
            "was_blocked": False,
            "block_ratio": 0.0,
            "cache_ratio": 0.4,
            "forward_ratio": 0.6,
            "qtype_counts": {"A": 3},
            "special_count": 0,
        },
    )
    handler = TextHandler(verbose_level=0)
    lines = handler._render_dns_group(_dns_sections([f]))
    output = "\n".join(lines)
    assert "BLOCKED" not in output, "was_blocked=False must not show BLOCKED token"


def test_text_renderer_pihole_verbose_shows_ratios() -> None:
    """Pihole singleton verbose output shows block/cache/fwd ratios; no rcode lines."""
    f = _make_dns_finding(
        Severity.HIGH,
        "a3f7bc19.example.com",
        {
            "source": "pihole",
            "label_score": 1.77,
            "query_count": 5,
            "unique_sources": 2,
            "querier_ips": ["192.0.2.1"],
            "was_blocked": True,
            "block_ratio": 0.5,
            "cache_ratio": 0.2,
            "forward_ratio": 0.3,
            "qtype_counts": {"A": 5},
            "special_count": 0,
        },
    )
    handler = TextHandler(verbose_level=1)
    lines = handler._render_dns_group(_dns_sections([f]))
    output = "\n".join(lines)

    # curated tail surfaces ratios as raw key:value pairs (no percent
    # formatting in the uniform evidence block).
    assert "block_ratio: 0.5" in output, "block_ratio must appear in verbose output"
    assert "was_blocked: True" in output, "was_blocked must appear in verbose output"
    # Pihole's qtype_counts is part of the pihole curated subset.
    assert "qtype_counts" in output, "qtype_counts must appear in pihole verbose"
    assert "rcode_distribution" not in output, "pihole verbose must not show rcode_distribution"


def test_text_renderer_zeek_default_line_unchanged() -> None:
    """Zeek-only singletons produce the character-identical pre-pihole format (no BLOCKED column)."""
    f1 = _make_dns_finding(
        Severity.HIGH,
        "sub.example.com",
        {
            "source": "zeek",
            "label_score": 2.10,
            "query_count": 5,
            "unique_sources": 2,
            "querier_ips": ["192.0.2.1"],
            "rcode_distribution": {},
        },
    )
    f2 = _make_dns_finding(
        Severity.HIGH,
        "api.example.net",
        {
            "source": "zeek",
            "label_score": 1.92,
            "query_count": 3,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.2"],
            "rcode_distribution": {},
        },
    )
    handler = TextHandler(verbose_level=0)
    lines = handler._render_dns_group(_dns_sections([f1, f2]))

    # Analytically derive expected strings - column widths are max across both rows:
    # score_w=10 ("score=2.10"), qry_w=5 ("5 qry"), src_w=5 ("2 src"), blocked_w=0 (no blocked)
    tag = f"{'[H]':<4}"  # "[H] "
    expected_1 = f"  {tag}  {'score=2.10':<10}  {'5 qry':>5}  {'2 src':>5}  sub.example.com"
    expected_2 = f"  {tag}  {'score=1.92':<10}  {'3 qry':>5}  {'1 src':>5}  api.example.net"

    # Row lines start with the 2-space indent + severity tag. Skip the
    # subsection label (e.g. "singletons (2)") and any blank lines.
    singleton_lines = [l for l in lines if l.startswith("  [")]
    assert singleton_lines[0] == expected_1, (
        f"line 1 mismatch:\n  got:      {singleton_lines[0]!r}\n  expected: {expected_1!r}"
    )
    assert singleton_lines[1] == expected_2, (
        f"line 2 mismatch:\n  got:      {singleton_lines[1]!r}\n  expected: {expected_2!r}"
    )
    assert "BLOCKED" not in "\n".join(lines), "Zeek-only output must not contain BLOCKED token"


def test_text_renderer_dns_sections_have_breathing_room() -> None:
    """DNS output separates detector and subgroup sections with blank lines."""
    singleton = _make_dns_finding(
        Severity.HIGH,
        "a3f7bc19.example.com",
        {
            "source": "pihole",
            "label_score": 1.77,
            "query_count": 5,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.1"],
            "was_blocked": False,
            "block_ratio": 0.0,
            "cache_ratio": 0.2,
            "forward_ratio": 0.8,
            "qtype_counts": {"A": 5},
            "special_count": 0,
        },
    )
    group = _make_dns_finding(
        Severity.MEDIUM,
        "example.com (2 subdomains, label_score >= 1.8)",
        {
            "source": "pihole",
            "registrable_domain": "example.com",
            "subdomain_count": 2,
            "max_label_score": 1.77,
            "min_label_score": 1.7,
            "total_queries": 8,
            "unique_sources": 2,
            "sample_domains": ["a3f7bc19.example.com", "m8x2q9n.example.com"],
            "querier_ips": ["192.0.2.1", "192.0.2.2"],
            "was_blocked": False,
            "block_ratio": 0.0,
            "cache_ratio": 0.2,
            "forward_ratio": 0.8,
            "qtype_counts": {"A": 8},
            "special_count": 0,
        },
    )

    lines = TextHandler(verbose_level=0)._render_dns_group(_dns_sections([singleton, group]))

    # The detector-level blank line above the groups subsection is emitted
    # by TextHandler.write (`print(file=stream)` before the header rule), not
    # by the renderer itself. Inside the renderer's output we only see the
    # gap BETWEEN sections.
    singleton_header = next(i for i, line in enumerate(lines) if "singletons" in line)
    assert lines[singleton_header - 1] == ""


def test_dns_partition_orders_groups_singletons_then_scan() -> None:
    """Reading sections lead with families and keep the scan summary trailing."""
    group = _make_dns_finding(
        Severity.MEDIUM,
        "family.example",
        {
            "source": "zeek",
            "registrable_domain": "family.example",
            "subdomain_count": 2,
            "max_label_score": 2.1,
            "min_label_score": 1.9,
            "total_queries": 3,
            "unique_sources": 1,
        },
    )
    singleton = _make_dns_finding(
        Severity.MEDIUM,
        "solo.example",
        {
            "source": "zeek",
            "label_score": 2.0,
            "query_count": 1,
            "unique_sources": 1,
        },
    )
    scan = _make_dns_finding(
        Severity.INFO,
        "dense-cluster scan",
        {
            "tier": "scan_summary",
            "cluster_count": 1,
            "total_members": 5,
        },
    )

    assert [section.label for section in _dns_sections([singleton, scan, group])] == [
        "groups",
        "singletons",
        "dense-cluster scan",
    ]


def test_text_renderer_zeek_verbose_rcode_unchanged() -> None:
    """Zeek singleton verbose output shows rcodes: line; no ratio lines."""
    f = _make_dns_finding(
        Severity.HIGH,
        "sub.example.com",
        {
            "source": "zeek",
            "label_score": 1.92,
            "query_count": 6,
            "unique_sources": 2,
            "querier_ips": ["192.0.2.1"],
            "rcode_distribution": {"NOERROR": 5, "NXDOMAIN": 1},
        },
    )
    handler = TextHandler(verbose_level=1)
    lines = handler._render_dns_group(_dns_sections([f]))
    output = "\n".join(lines)

    # curated tail: zeek singleton surfaces rcode_distribution as a raw
    # key:value pair (no per-detector ratio formatting).
    assert "rcode_distribution" in output, "Zeek verbose must show rcode_distribution"
    assert "NOERROR" in output, "rcode keys must appear"
    assert "block_ratio" not in output, "Zeek-only verbose must not show block_ratio"


def test_text_renderer_both_mode_verbose_shows_was_blocked() -> None:
    """Both-mode Zeek singleton with was_blocked=True shows was_blocked annotation in verbose."""
    f = _make_dns_finding(
        Severity.HIGH,
        "a3f7bc19.example.com",
        {
            "source": "zeek",
            "label_score": 1.77,
            "query_count": 3,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.1"],
            "rcode_distribution": {},
            "was_blocked": True,
            "block_ratio": 0.5,
        },
    )
    handler = TextHandler(verbose_level=1)
    lines = handler._render_dns_group(_dns_sections([f]))
    output = "\n".join(lines)

    # curated tail: both-mode (Zeek + Pi-hole enrichment) surfaces
    # was_blocked + block_ratio as raw key:value pairs. There is no "(Pi-hole
    # enrichment)" prose annotation in the per-detector block
    # - the keys themselves carry the provenance (a Zeek finding doesn't
    # have was_blocked otherwise).
    assert "was_blocked: True" in output, "both-mode verbose must show was_blocked"
    assert "block_ratio: 0.5" in output, "block_ratio must appear in both-mode verbose"


# ── Offline PSL pin - the "no phone-home" guard ───────────────────────────────
# common/tld.py owns the module-level extractor pinned to the bundled snapshot
# (suffix_list_urls=()), so a dns/hunt run never fetches the Public Suffix List
# over the network - keeping sigwood's "talks to no one" promise (docs/FAQ.md)
# true even on a cold cache / air-gapped box.

def test_tld_extract_is_owned_offline_and_shared_with_detector() -> None:
    """The common extractor is offline, cache-free, and the detector alias."""
    from sigwood.common.tld import TLD_EXTRACT
    from sigwood.detectors.dns import _TLD_EXTRACT

    assert _TLD_EXTRACT is TLD_EXTRACT
    assert TLD_EXTRACT.suffix_list_urls == ()


def test_tld_extract_cold_construction_never_opens_a_socket(monkeypatch) -> None:
    """The common owner's cold construction must never access the network."""
    from sigwood.common import tld

    def _no_network(*args, **kwargs):
        raise AssertionError(
            "offline pin breached - tldextract attempted network access"
        )

    monkeypatch.setattr(socket, "socket", _no_network)

    ext = tld._new_tld_extract()
    assert ext("foo.example.co.uk").top_domain_under_public_suffix == "example.co.uk"


# ── Dense-cluster scan (volume blind spot) ────────────────────────────────────
#
# A sustained high-volume tunnel self-clusters past min_cluster_size and escapes
# the noise-only label-score gate. The scan surfaces the dominant-registrable-domain
# members of clusters that are overwhelmingly high-entropy AND concentrated under
# one registrable domain. All domains are reserved `.example`; the high-entropy
# labels are consonant/digit stand-ins (no real infrastructure).

# No-vowel alphabet - high entropy() by construction (no vowel penalty).
_DGA_ALPHABET = "0123456789bcdfghjklmnpqrstvwxyz"


def _high_entropy_labels(n: int, *, seed: int = 7) -> list[str]:
    """n distinct labels each scoring >= 1.85 (margin above thresh_high_entropy
    1.8), so the scan's frac_hi gate is deterministically satisfied regardless of
    entropy() retuning. Derived from the live entropy() - not hardcoded."""
    rng = random.Random(seed)
    out: list[str] = []
    seen: set[str] = set()
    while len(out) < n:
        lbl = "".join(rng.sample(_DGA_ALPHABET, 18))
        if lbl in seen:
            continue
        seen.add(lbl)
        if dns_entropy(lbl) >= 1.85:
            out.append(lbl)
    return out


def _tunnel_extract(query: str) -> SimpleNamespace:
    """Per-query stub: registrable domain = the last two labels. Maps every
    `<label>.tunnel.example` to one parent (tunnel.example)."""
    parts = query.split(".")
    return SimpleNamespace(
        domain=parts[-2] if len(parts) >= 2 else parts[0],
        suffix=parts[-1],
        subdomain=".".join(parts[:-2]),
        top_domain_under_public_suffix=".".join(parts[-2:]) if len(parts) >= 2 else query,
    )


def test_dense_scan_concentrates_non_psl_cluster_under_private_root(
    monkeypatch,
) -> None:
    """A private-namespace cluster has top share 1.0 and can pass the scan."""
    import sigwood.detectors.dns as dns_mod

    queries = [f"{label}.lan" for label in _high_entropy_labels(100)]
    frame = pd.DataFrame({"query": queries})
    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _non_psl_extract)
    scan_cfg = {
        "scan_dense_clusters": True,
        "scan_min_high_entropy_fraction": 0.8,
        "scan_min_cluster_members": 100,
        "scan_min_regdomain_share": 0.8,
        "scan_max_members_per_cluster": 500,
    }

    records, dominant = dns_mod._surface_dense_clusters(
        frame,
        np.zeros(len(frame), dtype=int),
        thresh_high=1.8,
        scan_cfg=scan_cfg,
    )

    assert len(records) == len(queries)
    assert dominant == set(queries)
    keys = [
        dns_mod._registrable_key(query, _non_psl_extract(query))
        for query in queries
    ]
    top_share = pd.Series(keys).value_counts(normalize=True).iloc[0]
    assert top_share == 1.0

    monkeypatch.setattr(clustering, "HDBSCAN", _FakeAllCluster0)
    run_frame = frame.assign(
        ts=np.arange(len(frame), dtype=float),
        src="192.0.2.10",
    )
    findings = run(DetectorContext(
        logs={"dns*.log*": run_frame},
        config=_DENSE_CFG,
        allowlist=None,
        data_window=_WINDOW,
    ))
    groups = [
        finding
        for finding in findings
        if finding.evidence.get("registrable_domain") == "lan"
    ]
    assert len(groups) == 1
    assert groups[0].severity == Severity.HIGH
    assert groups[0].evidence["severity_basis"] == ["volume-concentration"]
    assert groups[0].description == (
        "Private namespace lan forms a dense, high-entropy cluster of 100 "
        "subdomains - the shape of DNS tunneling."
    )
    assert groups[0].next_steps == [
        "Check the local DNS zone or resolver that serves lan",
        "Confirm these names are expected on the internal network",
        "Check conn.log for connections to IPs resolved from these queries",
        "Pivot on querier IPs: 192.0.2.10",
    ]
    assert not any(
        marker in step
        for step in groups[0].next_steps
        for marker in ("whois", "VirusTotal")
    )


class _FakeAllCluster0:
    """HDBSCAN stand-in that puts every row in one non-noise cluster (label 0) -
    reproduces a fully self-clustering tunnel (zero noise)."""
    def __init__(self, **kwargs): pass
    def fit_predict(self, X: np.ndarray) -> np.ndarray:
        return np.zeros(X.shape[0], dtype=int)


def _fake_first_n_cluster(n_cluster: int):
    """HDBSCAN stand-in: first n_cluster rows → cluster 0, the rest → noise."""
    class _FH:
        def __init__(self, **kwargs): pass
        def fit_predict(self, X: np.ndarray) -> np.ndarray:
            labels = np.full(X.shape[0], -1, dtype=int)
            labels[:n_cluster] = 0
            return labels
    return _FH


def _fake_two_clusters(split: int):
    """HDBSCAN stand-in: rows [0:split) → cluster 0, [split:) → cluster 1."""
    class _FH:
        def __init__(self, **kwargs): pass
        def fit_predict(self, X: np.ndarray) -> np.ndarray:
            labels = np.ones(X.shape[0], dtype=int)
            labels[:split] = 0
            return labels
    return _FH


_DENSE_CFG = {"min_cluster_size": 50, "min_samples": 5}


def _dense_group_candidates(
    true_member_counts: tuple[int | None, ...],
) -> pd.DataFrame:
    """Candidate rows for one parent with dense and noise provenance."""
    labels = _high_entropy_labels(len(true_member_counts), seed=41)
    rows: list[dict] = []
    for index, (label, true_member_count) in enumerate(
        zip(labels, true_member_counts, strict=True)
    ):
        dense = true_member_count is not None
        rows.append({
            "query": f"{label}.tunnel.example",
            "label_entropy": dns_entropy(label),
            "registrable_domain": "tunnel.example",
            "has_public_suffix": True,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.10"],
            "source": "zeek",
            "query_count": 1,
            "rcode_distribution": {},
            "dense_cluster_id": float(index) if dense else np.nan,
            "cluster_true_member_count": (
                float(true_member_count) if dense else np.nan
            ),
            "cluster_true_query_total": (
                float(true_member_count) if dense else np.nan
            ),
        })
    return pd.DataFrame(rows)


def test_dense_group_noise_rows_cannot_satisfy_distinct_child_floor() -> None:
    """One dense child plus a noise sibling does not earn tunnel support."""
    findings = _shared_back_half(
        _dense_group_candidates((1, None)),
        threshold=1.8,
        now=_NOW,
        data_window=_WINDOW,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence["origin"] == "dense_cluster"
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["severity_basis"] == []
    assert "automated retry or rendezvous traffic" in finding.description
    assert "DNS tunneling" not in finding.description


def test_dense_group_any_qualifying_cluster_earns_tunnel_support() -> None:
    """One qualifying cluster is sufficient across mixed dense/noise rows."""
    findings = _shared_back_half(
        _dense_group_candidates((1, 2, None)),
        threshold=1.8,
        now=_NOW,
        data_window=_WINDOW,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.evidence["severity_basis"] == ["volume-concentration"]
    assert "DNS tunneling" in finding.description


def test_unrepresentable_event_time_carries_null_evidence() -> None:
    """A finite but out-of-range epoch cannot crash DNS finding creation."""
    import sigwood.detectors.dns as dns_mod

    assert dns_mod._event_time_evidence(1e20, 1e20) == {
        "first_seen": None,
        "last_seen": None,
        "span_seconds": None,
    }


@pytest.mark.parametrize("include_nan_ts", [False, True])
def test_zeek_missing_event_time_carries_null_evidence(
    monkeypatch: pytest.MonkeyPatch,
    include_nan_ts: bool,
) -> None:
    """A missing or all-NaN Zeek clock remains a valid carrying tier."""
    import sigwood.detectors.dns as dns_mod

    labels = _high_entropy_labels(2, seed=53)
    rows = [
        {
            "src": "192.0.2.10",
            "query": f"{label}.tunnel.example",
            **({"ts": np.nan} if include_nan_ts else {}),
        }
        for label in labels
    ]
    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _tunnel_extract)
    monkeypatch.setattr(
        dns_mod,
        "fit_predict_interruptible",
        lambda matrix, **kwargs: np.full(matrix.shape[0], -1, dtype=int),
    )

    findings = run(DetectorContext(
        logs={"dns*.log*": pd.DataFrame(rows)},
        config={
            **_DENSE_CFG,
            "scan_dense_clusters": False,
        },
        allowlist=None,
        data_window=_WINDOW,
    ))

    assert len(findings) == 1
    assert findings[0].evidence["first_seen"] is None
    assert findings[0].evidence["last_seen"] is None
    assert findings[0].evidence["span_seconds"] is None


def test_dense_scan_surfaces_high_volume_tunnel(monkeypatch) -> None:
    """A self-clustering high-volume tunnel carries a non-noise HDBSCAN label, so it
    never enters the noise-only candidate set; the dense-cluster scan surfaces it
    into the suspicion-score ranking. The reported subdomain count is the true
    dominant-domain count, independent of the per-cluster sample cap.

    Guards the failure mode where cluster_true_member_count /
    cluster_true_query_total are whole-cluster totals rather than
    dominant-registrable-domain counts.
    """
    import sigwood.detectors.dns as dns_mod

    labels = _high_entropy_labels(600)                       # > scan_max_members_per_cluster (500)
    tunnel = [f"{lbl}.tunnel.example" for lbl in labels]
    bg = ["www.example.com", "mail.example.com", "cdn.example.com"]  # readable/benign → noise
    rows = [
        {"ts": float(i), "src": "192.0.2.10", "query": q, "rcode": 3}
        for i, q in enumerate(tunnel)
    ]
    rows += [
        {"ts": float(1000 + i), "src": "192.0.2.20", "query": q, "rcode": 0}
        for i, q in enumerate(bg)
    ]
    df = pd.DataFrame(rows)

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _tunnel_extract)
    monkeypatch.setattr(clustering, "HDBSCAN", _fake_first_n_cluster(len(tunnel)))

    # With the scan disabled, a non-noise (clustered) tunnel is never a candidate.
    off = run(DetectorContext(logs={"dns*.log*": df.copy()},
                              config={**_DENSE_CFG, "scan_dense_clusters": False},
                              allowlist=None, data_window=_WINDOW))
    assert not any(f.evidence.get("registrable_domain") == "tunnel.example" for f in off)

    findings = run(DetectorContext(logs={"dns*.log*": df.copy()}, config=_DENSE_CFG,
                                   allowlist=None, data_window=_WINDOW))
    assert_report_voice(findings)

    grp = [f for f in findings if f.evidence.get("registrable_domain") == "tunnel.example"]
    assert len(grp) == 1, [f.title for f in findings]
    g = grp[0]
    assert g.evidence["origin"] == "dense_cluster"
    # True dominant-domain count, NOT the capped/sampled 500.
    assert g.evidence["subdomain_count"] == 600
    assert g.evidence["total_queries"] == 600

    # Full baseline DNS group evidence is present; dense + resolution
    # corroboration is explicit and ordered.
    _group_baseline = {
        "registrable_domain", "subdomain_count", "max_label_score", "min_label_score",
        "total_queries", "unique_sources", "sample_domains", "querier_ips",
    }
    assert _group_baseline <= set(g.evidence.keys())
    assert set(g.evidence.keys()) - _group_baseline == {
        "source", "origin", "severity_basis",
        "nxdomain_fraction", "nxdomain_count",
        "first_seen", "last_seen", "span_seconds",
    }
    assert g.severity == Severity.HIGH
    assert g.evidence["severity_basis"] == [
        "resolution-outcome", "volume-concentration",
    ]
    # The dense detector surfaces at most 500 member rows, so outcome evidence
    # is deliberately sample-relative while the structural totals above are 600.
    assert g.evidence["nxdomain_fraction"] == 1.0
    assert g.evidence["nxdomain_count"] == 500
    assert g.evidence["first_seen"] == "1970-01-01T00:00:00+00:00"
    assert g.evidence["last_seen"] == "1970-01-01T00:09:59+00:00"
    assert g.evidence["span_seconds"] == 599.0

    # Dense-origin prose - never the noise wording.
    assert "noise cluster" not in g.description
    assert "not clustered" not in g.description.lower()
    assert "dense" in g.description and "tunneling" in g.description
    assert g.description.endswith(
        "500 lookups under this name failed to resolve (100% of the total)."
    )
    assert g.description == (
        "Registrable domain tunnel.example forms a dense, high-entropy cluster "
        "of 600 subdomains - the shape of DNS tunneling. 500 lookups under this "
        "name failed to resolve (100% of the total)."
    )
    assert g.next_steps == [
        "Check domain registration: whois tunnel.example",
        "Look up tunnel.example on VirusTotal and Shodan",
        "Check conn.log for connections to IPs resolved from these queries",
        "Pivot on querier IPs: 192.0.2.10",
    ]

    summary = [f for f in findings if f.evidence.get("tier") == "scan_summary"]
    assert len(summary) == 1
    assert summary[0].severity == Severity.INFO
    assert summary[0].evidence["cluster_count"] >= 1
    assert summary[0].evidence["total_members"] == 600
    assert not {
        "first_seen", "last_seen", "span_seconds",
    } & set(summary[0].evidence)


def test_dense_scan_repeated_single_query_routes_to_singleton(monkeypatch) -> None:
    """A dense cluster of ONE repeated high-entropy query collapses (np.unique) to a
    single distinct candidate → singleton path. Pins the defensive singleton
    dense-origin prose branch, independent of the grouping invariant."""
    import sigwood.detectors.dns as dns_mod

    lbl = _high_entropy_labels(1)[0]
    q = f"{lbl}.tunnel.example"
    df = pd.DataFrame([{"ts": float(i), "src": "192.0.2.10", "query": q} for i in range(120)])

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _tunnel_extract)
    monkeypatch.setattr(clustering, "HDBSCAN", _FakeAllCluster0)

    findings = run(DetectorContext(logs={"dns*.log*": df}, config=_DENSE_CFG,
                                   allowlist=None, data_window=_WINDOW))
    assert_report_voice(findings)

    sng = [f for f in findings if f.title == q]
    assert len(sng) == 1, [f.title for f in findings]
    s = sng[0]
    assert "subdomain_count" not in s.evidence      # singleton, not a group
    assert s.evidence["origin"] == "dense_cluster"
    assert s.severity == Severity.MEDIUM
    assert s.evidence["severity_basis"] == []
    assert s.evidence["first_seen"] == "1970-01-01T00:00:00+00:00"
    assert s.evidence["last_seen"] == "1970-01-01T00:01:59+00:00"
    assert s.evidence["span_seconds"] == 119.0
    assert "noise cluster" not in s.description
    assert "not clustered" not in s.description.lower()
    assert "automated retry or rendezvous traffic" in s.description
    assert all(
        "DNS tunneling" not in finding.description
        and "treating as tunneling" not in (
            finding.description + " " + " ".join(finding.next_steps)
        )
        for finding in findings
    )
    assert any(f.evidence.get("tier") == "scan_summary" for f in findings)


def test_dense_scan_two_distinct_children_keep_tunnel_support(monkeypatch) -> None:
    """The minimum two-child dense cluster keeps its structural corroborator."""
    import sigwood.detectors.dns as dns_mod

    labels = _high_entropy_labels(2)
    queries = [f"{label}.tunnel.example" for label in labels]
    df = pd.DataFrame([
        {
            "ts": float(index),
            "src": "192.0.2.10",
            "query": queries[index % 2],
        }
        for index in range(120)
    ])

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _tunnel_extract)
    monkeypatch.setattr(clustering, "HDBSCAN", _FakeAllCluster0)

    findings = run(DetectorContext(
        logs={"dns*.log*": df},
        config=_DENSE_CFG,
        allowlist=None,
        data_window=_WINDOW,
    ))
    assert_report_voice(findings)

    groups = [
        finding
        for finding in findings
        if finding.evidence.get("registrable_domain") == "tunnel.example"
    ]
    assert len(groups) == 1
    group = groups[0]
    assert group.severity == Severity.HIGH
    assert group.evidence["severity_basis"] == ["volume-concentration"]
    assert "DNS tunneling" in group.description
    assert group.evidence["first_seen"] == "1970-01-01T00:00:00+00:00"
    assert group.evidence["last_seen"] == "1970-01-01T00:01:59+00:00"
    assert group.evidence["span_seconds"] == 119.0

    summary = next(
        finding
        for finding in findings
        if finding.evidence.get("tier") == "scan_summary"
    )
    assert "DNS tunneling" in summary.description
    assert not {
        "first_seen", "last_seen", "span_seconds",
    } & set(summary.evidence)


def test_dense_scan_regdomain_gate_rejects_multi_parent(monkeypatch) -> None:
    """A benign high-entropy cluster spread across DISTINCT registrable domains has
    top_regdomain_share below the gate → NOT surfaced. A per-query stub is required;
    a constant stub would return share 1.0 and pass vacuously."""
    import sigwood.detectors.dns as dns_mod

    parents = ["example.com", "example.net", "example.org"]
    labels = _high_entropy_labels(300)
    queries = [f"{lbl}.{parents[i % 3]}" for i, lbl in enumerate(labels)]  # ~1/3 each parent
    df = pd.DataFrame([{"ts": float(i), "src": "192.0.2.10", "query": q}
                       for i, q in enumerate(queries)])

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _tunnel_extract)   # per-query: last two labels
    monkeypatch.setattr(clustering, "HDBSCAN", _FakeAllCluster0)

    findings = run(DetectorContext(logs={"dns*.log*": df}, config=_DENSE_CFG,
                                   allowlist=None, data_window=_WINDOW))
    assert not any(f.evidence.get("origin") == "dense_cluster" for f in findings)
    assert not any(f.evidence.get("tier") == "scan_summary" for f in findings)


def test_dense_scan_disabled_surfaces_nothing(monkeypatch) -> None:
    """With scan_dense_clusters=false and an all-dense fixture, the noise set is empty
    and no cluster is surfaced, so the detector returns []."""
    import sigwood.detectors.dns as dns_mod

    tunnel = [f"{lbl}.tunnel.example" for lbl in _high_entropy_labels(600)]
    df = pd.DataFrame([{"ts": float(i), "src": "192.0.2.10", "query": q}
                       for i, q in enumerate(tunnel)])

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _tunnel_extract)
    monkeypatch.setattr(clustering, "HDBSCAN", _FakeAllCluster0)

    findings = run(DetectorContext(logs={"dns*.log*": df},
                                   config={**_DENSE_CFG, "scan_dense_clusters": False},
                                   allowlist=None, data_window=_WINDOW))
    assert findings == []


def test_dense_scan_query_shared_across_clusters_counted_once(monkeypatch) -> None:
    """A query whose rows split across TWO dense clusters under the same parent is
    attributed to ONE cluster (disjoint claim), so a shared subdomain is counted
    once - never doubled in subdomain_count or the scan-summary total."""
    import sigwood.detectors.dns as dns_mod

    labels = _high_entropy_labels(240)
    a, b = labels[:120], labels[120:240]        # disjoint subdomain sets
    shared = _high_entropy_labels(1, seed=99)[0]
    shared_q = f"{shared}.tunnel.example"

    c0 = [f"{lbl}.tunnel.example" for lbl in a] + [shared_q] * 5   # 125 rows → cluster 0
    c1 = [f"{lbl}.tunnel.example" for lbl in b] + [shared_q] * 5   # 125 rows → cluster 1
    queries = c0 + c1
    df = pd.DataFrame([{"ts": float(i), "src": "192.0.2.10", "query": q}
                       for i, q in enumerate(queries)])

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _tunnel_extract)
    monkeypatch.setattr(clustering, "HDBSCAN", _fake_two_clusters(len(c0)))

    findings = run(DetectorContext(logs={"dns*.log*": df}, config=_DENSE_CFG,
                                   allowlist=None, data_window=_WINDOW))

    grp = [f for f in findings if f.evidence.get("registrable_domain") == "tunnel.example"]
    assert len(grp) == 1
    # 120 + 120 + 1 shared subdomain counted ONCE (241) - NOT 242 (double-counted).
    assert grp[0].evidence["subdomain_count"] == 241
    summary = [f for f in findings if f.evidence.get("tier") == "scan_summary"][0]
    assert summary.evidence["cluster_count"] == 2
    assert summary.evidence["total_members"] == 241


def test_dense_scan_summary_never_exceeds_reported_findings(monkeypatch) -> None:
    """The scan surfaces on the thresh_high_entropy bar, but findings pass the
    back-half label_entropy >= threshold gate. When threshold is misconfigured
    above thresh_high_entropy every surfaced dense row is gated out, so the
    disclosure must stay silent - it can never claim a cluster the report does not
    show. The summary counts only gate-surviving clusters."""
    import sigwood.detectors.dns as dns_mod

    tunnel = [f"{lbl}.tunnel.example" for lbl in _high_entropy_labels(150)]  # label score ~1.9
    df = pd.DataFrame([{"ts": float(i), "src": "192.0.2.10", "query": q}
                       for i, q in enumerate(tunnel)])

    monkeypatch.setattr(dns_mod, "_TLD_EXTRACT", _tunnel_extract)
    monkeypatch.setattr(clustering, "HDBSCAN", _FakeAllCluster0)

    # threshold 5.0 > thresh_high_entropy 1.8: the scan surfaces the cluster, but the
    # back-half gate drops every member scoring ~1.9 → zero dense findings.
    findings = run(DetectorContext(
        logs={"dns*.log*": df},
        config={**_DENSE_CFG, "threshold": 5.0, "thresh_high_entropy": 1.8},
        allowlist=None, data_window=_WINDOW))

    assert not any(f.evidence.get("origin") == "dense_cluster" for f in findings)
    assert not any(f.evidence.get("tier") == "scan_summary" for f in findings)
