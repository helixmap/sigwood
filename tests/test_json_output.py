"""JSON handler - the lossless machine contract."""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

import sigwood
from sigwood.common.finding import (
    Finding,
    MethodTag,
    RunSummary,
    Severity,
    SuppressionSummary,
)
from sigwood.outputs.json import JsonHandler

_W = (
    datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
    datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
)


def _run_summary() -> RunSummary:
    return RunSummary(
        data_window=_W,
        record_counts={"conn*.log*": 3},
        data_size_bytes=2048,
        detectors_run=["beacon", "aws"],
        detectors_skipped={"dns": "no dns.log"},
        notes=["a note"],
        data_sources=["zeek_conn"],
        detector_methods={
            "beacon": MethodTag("FFT", True),
            "aws": MethodTag("statistical", False),
        },
        requested_span=timedelta(hours=6),
        suppression=SuppressionSummary(
            True, 5, 2, 100, 50,
            host_rows=7, host_total=70, hosts_matched=3,
        ),
    )


def _finding(evidence: dict, ts: datetime | None = None) -> Finding:
    return Finding(
        detector="beacon",
        severity=Severity.HIGH,
        title="192.0.2.10 → 192.0.2.20:443/tcp",
        description="A regular beat.",
        evidence=evidence,
        next_steps=["Inspect the flow"],
        ts_generated=ts or datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc),
        data_window=_W,
    )


def _emit(findings: list[Finding], *, verbose_level: int = 0) -> dict:
    buf = io.StringIO()
    h = JsonHandler(stream=buf, verbose_level=verbose_level)
    h.begin(_run_summary())
    h.write(findings)
    h.end()
    return json.loads(buf.getvalue())  # json.loads succeeds == valid JSON


def test_numpy_nan_set_evidence_is_valid_json() -> None:
    payload = _emit([_finding({
        "beacon_score": np.float64(0.61),
        "conn_count": np.int64(42),
        "ok": np.bool_(True),
        "states": {"SF", "S1"},
        "missing": float("nan"),
    })])
    ev = payload["findings"][0]["evidence"]
    assert isinstance(ev["beacon_score"], float)
    assert isinstance(ev["conn_count"], int) and not isinstance(ev["conn_count"], bool)
    assert ev["ok"] is True
    assert sorted(ev["states"]) == ["S1", "SF"]
    assert ev["missing"] is None


def test_envelope_has_version_and_schema() -> None:
    payload = _emit([_finding({})])
    assert payload["sigwood_version"] == sigwood.__version__
    assert payload["schema_version"] == 1


def test_run_summary_provenance_populated_and_nullable() -> None:
    summary = _run_summary()
    summary.invocation = "sigwood hunt 'quoted path/conn.log'"
    summary.generated_at = datetime(
        2026, 6, 1, 7, 30, tzinfo=timezone(timedelta(hours=-5)),
    )
    buf = io.StringIO()
    handler = JsonHandler(stream=buf)
    handler.begin(summary)
    handler.end()

    payload = json.loads(buf.getvalue())
    assert payload["schema_version"] == 1
    assert payload["sigwood_version"] == sigwood.__version__
    assert payload["run_summary"]["invocation"] == summary.invocation
    assert payload["run_summary"]["generated_at"] == (
        "2026-06-01T12:30:00+00:00"
    )

    nullable = _emit([])
    assert nullable["run_summary"]["invocation"] is None
    assert nullable["run_summary"]["generated_at"] is None


def test_invocation_controls_are_logically_lossless_but_json_escaped() -> None:
    controls = "".join(
        chr(cp) for cp in (*range(0x20), 0x7f, *range(0x80, 0xa0))
    )
    invocation = f"LEFT{controls}RIGHT"
    summary = _run_summary()
    summary.invocation = invocation
    buf = io.StringIO()
    handler = JsonHandler(stream=buf)
    handler.begin(summary)
    handler.end()
    source = buf.getvalue()

    assert json.loads(source)["run_summary"]["invocation"] == invocation
    assert "\\u001b" in source
    assert "\\u007f" in source
    assert "\\u009b" in source
    for ch in controls:
        if ch != "\n":
            assert ch not in source


def test_syslog_family_evidence_is_lossless_and_nullable() -> None:
    evidence = {
        "tier": "family",
        "host": "host-family",
        "program": "sshd",
        "line_count": 2,
        "program_total": 4412,
        "start_ts": None,
        "end_ts": None,
        "first_seen": None,
        "span_seconds": None,
        "sample_raw": ["raw-a", "raw-b"],
        "member_fragments": ["accepted from 192.0.2.9"],
        "label": None,
        "privileged": True,
    }
    family = Finding(
        detector="syslog",
        severity=Severity.MEDIUM,
        title="host-family",
        description="A set of rare log lines.",
        evidence=evidence,
        next_steps=["Skim the sampled lines"],
        ts_generated=datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc),
        data_window=_W,
    )
    payload = _emit([family])

    assert payload["schema_version"] == 1
    assert payload["findings"][0]["evidence"] == evidence


def test_syslog_transaction_evidence_is_additive_without_schema_bump() -> None:
    evidence = {
        "tier": "transaction",
        "label": "update run",
        "host": "host-a",
        "member_count": 2,
        "represented_line_count": 4,
        "start_ts": 1.0,
        "end_ts": 61.0,
        "first_seen": "1970-01-01T00:00:01+00:00",
        "span_seconds": 60.0,
        "program_mix": [["dnf", 3], ["kernel", 1]],
        "members": [
            {"severity": "low", "tier": "family", "represented_line_count": 3,
             "title": "host-a", "first_seen": "1970-01-01T00:00:02+00:00",
             "program": "dnf", "sample_raw": ["dnf-raw-a", "dnf-raw-b"]},
            {"severity": "low", "represented_line_count": 1,
             "title": "kernel: package event",
             "first_seen": "1970-01-01T00:00:03+00:00", "program": "kernel"},
        ],
    }
    transaction = Finding(
        detector="syslog", severity=Severity.INFO, title="host-a",
        description="Recognized system update activity.", evidence=evidence,
        next_steps=["Review the member findings"],
        ts_generated=datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc),
        data_window=_W,
    )

    payload = _emit([transaction])

    assert payload["schema_version"] == 1
    assert payload["findings"][0]["evidence"] == evidence
    members = payload["findings"][0]["evidence"]["members"]
    assert [member["title"] for member in members] == [
        "host-a", "kernel: package event",
    ]
    assert members[0]["sample_raw"] == ["dnf-raw-a", "dnf-raw-b"]
    assert "tier" not in members[1]
    assert "sample_raw" not in members[1]


def test_syslog_needle_stamp_evidence_is_lossless_without_schema_bump() -> None:
    evidence = {
        "host": "host-journal",
        "program": "cron",
        "template_str": "cron: journal needle sentinel",
        "count": 1,
        "threshold": 9,
        "first_seen": None,
        "self_stamped": False,
    }
    needle = Finding(
        detector="syslog",
        severity=Severity.LOW,
        title="journal needle sentinel",
        description="Rare template.",
        evidence=evidence,
        next_steps=["Review surrounding log context"],
        ts_generated=datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc),
        data_window=_W,
    )
    payload = _emit([needle])

    assert payload["schema_version"] == 1
    assert payload["findings"][0]["evidence"] == evidence
    assert payload["findings"][0]["evidence"]["self_stamped"] is False
    assert payload["findings"][0]["evidence"]["first_seen"] is None


def test_dns_label_score_evidence_keys_reach_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """A dns finding's JSON evidence carries only the label-score keys, never the
    legacy entropy keys: group findings expose max_label_score / min_label_score,
    singletons expose label_score, and no dns finding carries entropy / max_entropy
    / min_entropy. Pins the machine surface behind schema_version 1.
    """
    from types import SimpleNamespace

    import pandas as pd

    from sigwood.common import clustering
    from sigwood.common.finding import DetectorContext
    import sigwood.detectors.dns as dns_mod

    # In-process clustering so the fake clusterer is visible to this process
    # (mirrors tests/test_dns_detector.py's harness).
    monkeypatch.setattr(clustering, "_CLUSTERING_ISOLATE_ENABLED", False)

    # Two subdomains of one registrable domain (a group) + one lone high-score
    # subdomain (a singleton). RFC 5737 / reserved-domain fixtures.
    df = pd.DataFrame([
        {"ts": 1.0, "src": "192.0.2.1", "query": "safe.example.com"},          # cluster 0
        {"ts": 2.0, "src": "192.0.2.2", "query": "normal.example.org"},        # cluster 0
        {"ts": 3.0, "src": "192.0.2.1", "query": "a3f7bc19.malware.example"},  # noise -> group
        {"ts": 4.0, "src": "192.0.2.2", "query": "m8x2q9n.malware.example"},   # noise -> group
        {"ts": 5.0, "src": "192.0.2.1", "query": "k8x2m5q7n1p.suspect.example"},  # noise -> singleton
    ])
    ext = {
        "safe.example.com":            SimpleNamespace(domain="example", suffix="com", subdomain="safe", top_domain_under_public_suffix="example.com"),
        "normal.example.org":          SimpleNamespace(domain="example", suffix="org", subdomain="normal", top_domain_under_public_suffix="example.org"),
        "a3f7bc19.malware.example":    SimpleNamespace(domain="malware", suffix="example", subdomain="a3f7bc19", top_domain_under_public_suffix="malware.example"),
        "m8x2q9n.malware.example":     SimpleNamespace(domain="malware", suffix="example", subdomain="m8x2q9n", top_domain_under_public_suffix="malware.example"),
        "k8x2m5q7n1p.suspect.example": SimpleNamespace(domain="suspect", suffix="example", subdomain="k8x2m5q7n1p", top_domain_under_public_suffix="suspect.example"),
    }
    monkeypatch.setattr(
        dns_mod, "_TLD_EXTRACT",
        lambda q: ext.get(q, SimpleNamespace(domain="", suffix="", subdomain="", top_domain_under_public_suffix="")),
    )

    class _FakeHDBSCAN:
        def __init__(self, **kwargs): pass
        def fit_predict(self, X):  # rows 0-1 cluster, 2-4 noise
            return np.array([0, 0, -1, -1, -1])

    monkeypatch.setattr(clustering, "HDBSCAN", _FakeHDBSCAN)

    ctx = DetectorContext(
        logs={"dns*.log*": df},
        config={"min_cluster_size": 5, "min_samples": 1, "threshold": 1.5, "thresh_high_entropy": 1.8},
        allowlist=None,
        data_window=_W,
    )
    findings = dns_mod.run(ctx)
    assert findings, "expected a dns group + singleton"

    payload = _emit(findings)
    assert payload["schema_version"] == 1

    dns_ev = [f["evidence"] for f in payload["findings"] if f["detector"] == "dns"]
    group = [ev for ev in dns_ev if "subdomain_count" in ev]
    singleton = [ev for ev in dns_ev if "subdomain_count" not in ev]
    assert group and singleton, "expected both a group and a singleton dns finding"

    for ev in group:
        assert "max_label_score" in ev and "min_label_score" in ev
    for ev in singleton:
        assert "label_score" in ev

    legacy = {"entropy", "max_entropy", "min_entropy"}
    for ev in dns_ev:
        leaked = legacy & set(ev)
        assert not leaked, f"legacy entropy keys leaked into JSON: {leaked}"


def test_run_summary_added_fields_present() -> None:
    rs = _emit([_finding({})])["run_summary"]
    assert rs["detector_methods"] == {
        "beacon": {"label": "FFT", "named": True},
        "aws": {"label": "statistical", "named": False},
    }
    assert rs["requested_span"] == 6 * 3600
    assert rs["data_sources"] == ["zeek_conn"]
    assert rs["suppression"]["connection_total"] == 100
    assert rs["suppression"]["host_rows"] == 7
    assert rs["suppression"]["host_total"] == 70
    assert rs["suppression"]["hosts_matched"] == 3


def test_no_severity_tag() -> None:
    f = _emit([_finding({})])["findings"][0]
    assert "severity_tag" not in f
    assert f["severity"] == "high"


def test_non_utc_datetime_serializes_as_utc() -> None:
    # An aware datetime at +05:00 must serialize as its UTC equivalent, not echo +05:00.
    ts = datetime(2026, 6, 1, 18, 0, tzinfo=timezone(timedelta(hours=5)))
    f = _emit([_finding({}, ts=ts)])["findings"][0]
    assert f["ts_generated"] == "2026-06-01T13:00:00+00:00"
    assert "+05:00" not in f["ts_generated"]


def test_window_stays_iso_utc() -> None:
    payload = _emit([_finding({})])
    assert payload["run_summary"]["data_window"][0] == "2026-06-01T12:00:00+00:00"


def test_window_null_when_no_data() -> None:
    """data_window=None serializes as JSON null - the machine summary never
    invents a window."""
    buf = io.StringIO()
    h = JsonHandler(stream=buf, verbose_level=0)
    h.begin(RunSummary(
        data_window=None,
        record_counts={},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
    ))
    h.write([])
    h.end()
    payload = json.loads(buf.getvalue())
    assert payload["run_summary"]["data_window"] is None


def test_verbosity_invariant() -> None:
    f = [_finding({"beacon_score": np.float64(0.5)})]
    assert _emit(f, verbose_level=0) == _emit(f, verbose_level=2)


def test_allow_nan_false_guards_the_writer() -> None:
    """Prove the HANDLER's final ``json.dump(..., allow_nan=False)`` guard, not
    stdlib behavior or the normalized happy path: monkeypatch the serialization
    helper at the handler seam to a passthrough so an un-normalised nan reaches
    the writer - it MUST raise rather than emit bare ``NaN``."""
    import sigwood.outputs.json as json_mod

    original = json_mod.to_jsonable
    json_mod.to_jsonable = lambda value: value  # identity - defeat normalisation
    try:
        buf = io.StringIO()
        h = JsonHandler(stream=buf, verbose_level=0)
        h.begin(_run_summary())
        h.write([_finding({"slipped": float("nan")})])
        with pytest.raises(ValueError):
            h.end()
        assert "NaN" not in buf.getvalue()
    finally:
        json_mod.to_jsonable = original


# ── display timezone switch: the machine feed never reads it ──────────────────
def test_payload_invariant_under_display_switch(pin_tz, restore_display_utc) -> None:
    """The json feed is byte-identical with the display switch off and on -
    the knob must not reach ``_iso_utc`` (ISO-8601 UTC either way), even under
    a non-UTC machine zone."""
    from sigwood.common.display import set_display_utc

    pin_tz("Etc/GMT+6")
    findings = [_finding({"beacon_score": 0.61})]

    def _render() -> str:
        buf = io.StringIO()
        h = JsonHandler(stream=buf, verbose_level=0)
        h.begin(_run_summary())
        h.write(findings)
        h.end()
        return buf.getvalue()

    off_bytes = _render()
    set_display_utc(True)
    on_bytes = _render()

    assert off_bytes == on_bytes
    assert "2026-06-01T12:00:00+00:00" in off_bytes  # window start, ISO-8601 UTC


def test_detectors_failed_serialized() -> None:
    """A crashed detector's failure record rides the machine feed - name →
    phase-prefixed reason - so a scheduled run's consumer can alert on it."""
    buf = io.StringIO()
    h = JsonHandler(stream=buf, verbose_level=0)
    summary = _run_summary()
    # Written during the detector loop (after begin) - the handler serializes
    # at end(), so the mutation must be visible in the payload.
    h.begin(summary)
    summary.detectors_failed["beacon"] = "detector error - boom"
    h.write([])
    h.end()
    payload = json.loads(buf.getvalue())
    assert payload["run_summary"]["detectors_failed"] == {
        "beacon": "detector error - boom"
    }


def test_detectors_failed_empty_on_clean_run() -> None:
    """A clean run carries an explicit empty dict - consumers test length,
    never key presence."""
    payload = _emit([])
    assert payload["run_summary"]["detectors_failed"] == {}
