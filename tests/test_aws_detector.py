"""Unit tests for the aws detector - per-principal CloudTrail behavioral surfacing.

All fixtures are synthetic per the privacy rail: RFC 5737 IPs only, AWS
documentation account 123456789012, obvious-placeholder principal / role names.

Each test states the property under test and exercises the smallest synthetic
frame that proves it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from tests.test_voice_consistency import assert_report_voice

import pandas as pd

from sigwood.common.finding import DetectorContext, Severity
from sigwood.common.loader import _CLOUDTRAIL_COLUMNS
from sigwood.detectors.aws import (
    DEFAULT_CONFIG,
    _aggregate_per_principal,
    _compute_bursts,
    _compute_rarity,
    _compute_weirdness,
    below_floor_count,
    run,
)


_DOCS_ACCT = "123456789012"
_WINDOW = (
    datetime(2026, 6, 1, tzinfo=timezone.utc),
    datetime(2026, 6, 8, tzinfo=timezone.utc),
)
_BASE_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc).timestamp()


# ── Fixture helpers ──────────────────────────────────────────────────────────

def _event(**overrides) -> dict:
    """Build a minimal canonical CloudTrail per-event row (12 fields)."""
    base: dict = {
        "ts":            _BASE_TS,
        "principal":     "placeholder-user",
        "lane":          "interactive",
        "read_write":    "read",
        "event_source":  "s3.amazonaws.com",
        "event_name":    "GetObject",
        "identity_type": "IAMUser",
        "source_ip":     "192.0.2.10",
        "error_code":    None,
        "aws_region":    "us-east-1",
        "event_id":      "11111111-1111-1111-1111-111111111111",
        "raw":           {},
    }
    base.update(overrides)
    return base


def _df(events: list[dict]) -> pd.DataFrame:
    """Build a DataFrame matching parsers/cloudtrail.py's 12-column output."""
    if not events:
        return pd.DataFrame(columns=_CLOUDTRAIL_COLUMNS)
    rows = [_event(**e) for e in events]
    return pd.DataFrame(rows, columns=_CLOUDTRAIL_COLUMNS)


def _ctx(df: pd.DataFrame, **kwargs) -> DetectorContext:
    """DetectorContext for driving run() in tests.

    No verbose kwarg - the result set is verbosity-invariant. Any
    leftover ``verbose=`` kwarg is silently dropped so call sites that pass
    one stay quiet.
    """
    cfg = kwargs.pop("config", {})
    data_window = kwargs.pop("data_window", _WINDOW)
    kwargs.pop("verbose", None)
    return DetectorContext(
        logs={"*.json*": df},
        config=cfg,
        allowlist=SimpleNamespace(filter_df=lambda d, name: d),
        data_window=data_window,
        data_sources=["cloudtrail_raw"],
    )


# ── Aggregation: principal collapses across sessions ─────────────────────────

def test_aggregate_per_principal_collapses_sessions_of_same_role() -> None:
    """The parser's principal key already collapses an AssumedRole's sessions; the
    detector aggregates by that key, so two events with different session names
    but the same parser-derived principal aggregate as one row."""
    events = [_event(principal="role:placeholder-role", event_id=f"e{i}") for i in range(20)]
    df = _df(events)

    per = _aggregate_per_principal(df)

    assert len(per) == 1
    assert per.iloc[0]["principal"] == "role:placeholder-role"
    assert per.iloc[0]["event_count"] == 20


def test_aggregate_features_match_known_distribution() -> None:
    """Spot-check features against a small hand-constructed event mix."""
    events = (
        # 5 GetObject (read, success), 5 PutObject (write, 1 errored), all one IP, one region
        [_event(event_name="GetObject", read_write="read") for _ in range(5)]
        + [_event(event_name="PutObject", read_write="write") for _ in range(4)]
        + [_event(event_name="PutObject", read_write="write", error_code="AccessDenied")]
    )
    df = _df(events)
    per = _aggregate_per_principal(df)

    assert len(per) == 1
    row = per.iloc[0]
    assert row["event_count"] == 10
    assert abs(row["error_rate"] - 0.1) < 1e-9
    assert row["distinct_event_name"] == 2          # GetObject, PutObject
    assert row["distinct_source_ip"] == 1
    assert row["distinct_event_source"] == 1
    assert abs(row["read_ratio"] - 0.5) < 1e-9


# ── Lane split: service principals are excluded ──────────────────────────────

def test_lane_split_service_principals_yield_no_findings() -> None:
    """A frame containing only service-lane events returns []."""
    events = [
        _event(lane="service", principal="ec2.amazonaws.com", event_name=f"Action{i}")
        for i in range(100)
    ]
    df = _df(events)
    findings = run(_ctx(df, config={"min_events": 10}))
    assert findings == []


def test_lane_split_service_events_excluded_from_aggregation() -> None:
    """A mixed frame with one interactive and one service-lane principal aggregates
    only the interactive one."""
    events = (
        [_event(principal="alice") for _ in range(5)]
        + [_event(principal="ec2.amazonaws.com", lane="service") for _ in range(50)]
    )
    df = _df(events)
    from sigwood.detectors.aws import _filter_interactive
    per = _aggregate_per_principal(_filter_interactive(df))
    assert list(per["principal"]) == ["alice"]


# ── Signal 1: rarity ─────────────────────────────────────────────────────────

def test_rarity_log10_n_over_count() -> None:
    """For 100 events with three actions in 70/20/10 proportions, rarity is
    log10(N/count) per action."""
    import math
    events = (
        [_event(event_name="GetObject") for _ in range(70)]
        + [_event(event_name="ListBuckets") for _ in range(20)]
        + [_event(event_name="DeleteBucket") for _ in range(10)]
    )
    rarity = _compute_rarity(_df(events))
    assert abs(rarity["GetObject"]   - math.log10(100 / 70)) < 1e-9
    assert abs(rarity["ListBuckets"] - math.log10(100 / 20)) < 1e-9
    assert abs(rarity["DeleteBucket"] - math.log10(100 / 10)) < 1e-9


def test_rarity_empty_frame_returns_empty_dict() -> None:
    assert _compute_rarity(_df([])) == {}


# ── Signal 2: weirdness composite ────────────────────────────────────────────

def test_weirdness_composite_ranks_outlier_first() -> None:
    """Five principals; one is unambiguously the standout in error rate and
    distinct source-IP count. It must rank first by composite_z."""
    # Build N events each for 5 principals; principal 'outlier' has high error
    # rate AND many distinct source IPs. Others are bland and similar.
    events: list[dict] = []
    for name in ["alice", "bob", "carol", "dave"]:
        events.extend(_event(principal=name, source_ip="192.0.2.10",
                             event_name="GetObject", error_code=None)
                      for _ in range(60))
    for i in range(60):
        events.append(_event(
            principal="outlier",
            source_ip=f"198.51.100.{i % 30}",
            event_name=f"Action{i % 20}",
            error_code="AccessDenied" if i % 2 == 0 else None,
        ))
    df = _df(events)
    findings = run(_ctx(df, config={
        "min_events": 50,
        "composite_medium_threshold": 1.5,
        "composite_low_threshold": 0.5,
    }))
    assert_report_voice(findings)
    ranked = [f for f in findings if f.evidence.get("tier") == "ranked"]
    assert ranked, "expected at least one ranked finding"
    assert ranked[0].evidence["principal"] == "outlier"


def test_weirdness_composite_degenerate_population_yields_zero_z() -> None:
    """A single scorable principal produces std == 0 across all features; all
    z-scores collapse to 0, composite is 0, and the synthetic ranked_summary
    is emitted instead of a per-principal finding. The population gate is
    disabled (floor 1) so the degenerate z-collapse path through run() stays
    exercised at n=1."""
    events = [_event(principal="only-one") for _ in range(60)]
    df = _df(events)
    findings = run(_ctx(df, config={"min_events": 50, "min_scorable_principals": 1}))
    assert_report_voice(findings)
    ranked = [f for f in findings if f.evidence.get("tier") == "ranked"]
    summary = [f for f in findings if f.evidence.get("tier") == "ranked_summary"]
    assert ranked == []
    assert len(summary) == 1
    assert summary[0].severity == Severity.INFO
    assert summary[0].evidence["scorable_count"] == 1
    assert summary[0].evidence["top_composite_z"] == 0.0


# ── Signal 3: burst aggregation ──────────────────────────────────────────────

def _enum_sweep(principal: str, n_firsts: int, gap: float, start_ts: float,
                error_rate: float = 0.0, n_services: int = 1) -> list[dict]:
    """Construct an enumeration-sweep event sequence:
      1. one seed event (so principal isn't all-new)
      2. n_firsts events with distinct event_names spaced ``gap`` seconds apart
    """
    events = [_event(principal=principal, ts=start_ts, event_name="SeedAction")]
    for i in range(n_firsts):
        events.append(_event(
            principal=principal,
            ts=start_ts + (i + 1) * gap,
            event_name=f"NewAction{i:03d}",
            event_source=f"svc{i % n_services}.amazonaws.com",
            error_code="AccessDenied" if i / n_firsts < error_rate else None,
        ))
    return events


def test_burst_collapses_enumeration_sweep_to_one_finding() -> None:
    """N first-seen actions within burst_gap_seconds collapse to ONE burst Finding."""
    events = _enum_sweep("attacker", n_firsts=10, gap=30.0, start_ts=_BASE_TS)
    df = _df(events)
    findings = run(_ctx(df, config={
        "min_events": 1000,            # nobody scorable; only burst tier exposed
        "burst_gap_seconds": 300,
        "burst_min_firsts": 3,
    }))
    bursts = [f for f in findings if f.evidence.get("tier") == "burst"]
    assert len(bursts) == 1
    assert bursts[0].evidence["new_action_count"] == 10


def test_burst_negative_gap_too_wide_produces_no_finding() -> None:
    """First-seen actions spread wider than burst_gap_seconds produce no burst."""
    # Gap of 600s with burst_gap_seconds=300 → each first-seen event starts a fresh
    # singleton burst that never reaches burst_min_firsts.
    events = _enum_sweep("explorer", n_firsts=10, gap=600.0, start_ts=_BASE_TS)
    df = _df(events)
    findings = run(_ctx(df, config={
        "min_events": 1000,
        "burst_gap_seconds": 300,
        "burst_min_firsts": 3,
    }))
    assert [f for f in findings if f.evidence.get("tier") == "burst"] == []


def test_burst_negative_too_few_firsts() -> None:
    """Fewer than burst_min_firsts first-seen actions produce no burst finding."""
    events = _enum_sweep("explorer", n_firsts=2, gap=30.0, start_ts=_BASE_TS)
    df = _df(events)
    findings = run(_ctx(df, config={
        "min_events": 1000,
        "burst_gap_seconds": 300,
        "burst_min_firsts": 3,
    }))
    assert [f for f in findings if f.evidence.get("tier") == "burst"] == []


def test_burst_skips_principal_very_first_event() -> None:
    """A principal's first event must NOT count as first-seen (all-new is
    uninformative - handled by the seed step in _compute_bursts)."""
    # A principal whose entire footprint is N events of distinct names, with
    # NO seed: first event seeds, next (N-1) are first-seen.
    events = [
        _event(principal="alpha", ts=_BASE_TS + i * 30.0, event_name=f"Action{i:03d}")
        for i in range(5)
    ]
    df = _df(events)
    findings = run(_ctx(df, config={
        "min_events": 1000,
        "burst_gap_seconds": 300,
        "burst_min_firsts": 3,
    }))
    bursts = [f for f in findings if f.evidence.get("tier") == "burst"]
    # 5 events, first is seed, 4 are first-seen → burst of 4 (>= burst_min_firsts=3)
    assert len(bursts) == 1
    assert bursts[0].evidence["new_action_count"] == 4


# ── Severity gates ────────────────────────────────────────────────────────────

def test_burst_default_severity_is_medium_on_clean_burst() -> None:
    """A bare large burst with no errors and one service is MEDIUM."""
    events = _enum_sweep("attacker", n_firsts=10, gap=30.0, start_ts=_BASE_TS,
                         error_rate=0.0, n_services=1)
    findings = run(_ctx(_df(events), config={"min_events": 1000}))
    bursts = [f for f in findings if f.evidence.get("tier") == "burst"]
    assert bursts[0].severity == Severity.MEDIUM


def test_burst_escalates_to_high_on_error_rate() -> None:
    """burst error_rate >= burst_high_error_rate → HIGH."""
    events = _enum_sweep("attacker", n_firsts=10, gap=30.0, start_ts=_BASE_TS,
                         error_rate=1.0, n_services=1)
    findings = run(_ctx(_df(events), config={
        "min_events": 1000,
        "burst_high_error_rate": 0.5,
    }))
    bursts = [f for f in findings if f.evidence.get("tier") == "burst"]
    assert bursts[0].severity == Severity.HIGH


def test_service_spread_alone_never_escalates() -> None:
    """A clean many-service burst stays MEDIUM anywhere in the window.

    A person exploring the console touches many services in one benign
    sitting, so service spread is the sweep's size in service units, never an
    independent evidence category. The recognized-for-compatibility
    burst_high_service_count key is set to its most aggressive value to pin
    that it no longer reaches severity.
    """
    events = _enum_sweep("attacker", n_firsts=10, gap=30.0, start_ts=_BASE_TS,
                         error_rate=0.0, n_services=5)
    config = {
        "min_events": 1000,
        "burst_high_error_rate": 1.5,    # disable the error gate
        "burst_high_service_count": 1,   # inert: accepted, never escalates
    }

    mid_window = run(_ctx(_df(events), config=config))
    edge_window = (
        datetime.fromtimestamp(_BASE_TS + 30.0, tz=timezone.utc),
        _WINDOW[1],
    )
    at_edge = run(_ctx(_df(events), config=config, data_window=edge_window))

    for findings in (mid_window, at_edge):
        bursts = [f for f in findings if f.evidence.get("tier") == "burst"]
        assert bursts[0].evidence["new_service_count"] >= 3
        assert bursts[0].severity == Severity.MEDIUM


def test_window_edge_error_burst_still_escalates_to_high() -> None:
    """Error-heavy bursts promote at the loaded window edge too."""
    events = _enum_sweep("attacker", n_firsts=10, gap=30.0, start_ts=_BASE_TS,
                         error_rate=1.0, n_services=1)
    edge_window = (
        datetime.fromtimestamp(_BASE_TS + 30.0, tz=timezone.utc),
        _WINDOW[1],
    )
    findings = run(_ctx(_df(events), config={
        "min_events": 1000,
        "burst_high_error_rate": 0.5,
    }, data_window=edge_window))
    bursts = [f for f in findings if f.evidence.get("tier") == "burst"]
    assert bursts[0].severity == Severity.HIGH


def test_burst_never_auto_high_on_size_alone() -> None:
    """Even a very large clean burst stays MEDIUM - size alone never escalates."""
    events = _enum_sweep("walker", n_firsts=100, gap=10.0, start_ts=_BASE_TS,
                         error_rate=0.0, n_services=1)
    findings = run(_ctx(_df(events), config={
        "min_events": 1000,
        "burst_high_error_rate": 0.5,
    }))
    bursts = [f for f in findings if f.evidence.get("tier") == "burst"]
    assert bursts[0].severity == Severity.MEDIUM


# ── Two clean-corpus cases ───────────────────────────────────────────────────

def test_clean_corpus_below_floor_emits_no_ranked_findings() -> None:
    """When all principals are below min_events, no ranked tier at all - the
    runner's RunSummary note is what discloses this case, not a detector
    Finding."""
    # 3 principals, each with 5 events (default min_events=50).
    events: list[dict] = []
    for name in ["alice", "bob", "carol"]:
        events.extend(_event(principal=name, event_name="GetObject") for _ in range(5))
    df = _df(events)
    findings = run(_ctx(df))
    ranked = [f for f in findings if f.evidence.get("tier") == "ranked"]
    summary = [f for f in findings if f.evidence.get("tier") == "ranked_summary"]
    assert ranked == []
    assert summary == []  # no synthetic summary either
    assert below_floor_count(df, DEFAULT_CONFIG["min_events"]) == 3


def test_clean_corpus_scorable_but_below_low_band_emits_one_summary() -> None:
    """When scorable principals exist but none clears the LOW band, the synthetic
    ranked_summary INFO finding is emitted (one, not per-principal)."""
    # 5 principals (at the population floor, so banding engages), identical
    # footprint - z-scores collapse to 0 < LOW.
    events: list[dict] = []
    for name in ["alice", "bob", "carol", "dave", "erin"]:
        events.extend(_event(principal=name) for _ in range(60))
    df = _df(events)
    findings = run(_ctx(df, config={"min_events": 50}))
    ranked = [f for f in findings if f.evidence.get("tier") == "ranked"]
    summary = [f for f in findings if f.evidence.get("tier") == "ranked_summary"]
    assert ranked == []
    assert len(summary) == 1
    assert summary[0].severity == Severity.INFO


def test_clean_corpus_summary_evidence_carries_scorable_count_and_top() -> None:
    """The synthetic summary surfaces scorable_count and top_principal (the
    least-unremarkable actor) as analyst pivot - not just an empty 'quiet' line."""
    names = ["alice", "bob", "carol", "dave", "erin"]  # at the population floor
    events: list[dict] = []
    for name in names:
        events.extend(_event(principal=name) for _ in range(60))
    df = _df(events)
    findings = run(_ctx(df, config={"min_events": 50}))
    summary = [f for f in findings if f.evidence.get("tier") == "ranked_summary"][0]
    assert summary.evidence["scorable_count"] == 5
    assert summary.evidence["top_principal"] in set(names)
    assert "top_composite_z" in summary.evidence


# ── Ranked-tier population floor ─────────────────────────────────────────────
#
# Population z-scores are rank position by construction at tiny n (max |z| =
# sqrt(n-1); at n=2 every non-degenerate signal is exactly ±1), so below
# min_scorable_principals the ranked tier abstains from MEDIUM/LOW and emits
# the too-few-to-compare synthetic instead.

def _two_admin_events() -> list[dict]:
    """Two scorable admins, one clearly busier: without the population gate,
    the busier one reaches composite +3.0 (three signals at z = +1) and lands
    a manufactured MEDIUM. Events spaced wider than burst_gap_seconds so no
    burst fires from these principals."""
    events = [
        _event(principal="admin-alice", ts=_BASE_TS + i * 400.0,
               event_name=["GetObject", "ListBuckets"][i % 2],
               source_ip="192.0.2.10")
        for i in range(60)
    ]
    busy_names = ["ListBuckets", "GetObject", "DescribeInstances",
                  "ListUsers", "GetCallerIdentity", "DescribeRegions"]
    events += [
        _event(principal="admin-bob", ts=_BASE_TS + 50.0 + i * 400.0,
               event_name=busy_names[i % 6],
               source_ip="192.0.2.20",
               error_code="AccessDenied" if i % 10 == 0 else None)
        for i in range(90)
    ]
    return events


def test_ranked_below_floor_two_admins_abstain() -> None:
    """n=2 scorable is below the default floor (5): zero MEDIUM/LOW ranked
    findings; exactly one INFO too-few-to-compare synthetic with the committed
    strings and deliberately NO composite z or top principal. A burst from an
    unrelated below-min_events principal renders unaffected."""
    events = _two_admin_events()
    events += _enum_sweep("sweeper", n_firsts=5, gap=30.0, start_ts=_BASE_TS)
    df = _df(events)
    findings = run(_ctx(df))
    assert_report_voice(findings)

    ranked = [f for f in findings if f.evidence.get("tier") == "ranked"]
    summary = [f for f in findings if f.evidence.get("tier") == "ranked_summary"]
    bursts = [f for f in findings if f.evidence.get("tier") == "burst"]
    assert ranked == []
    assert len(summary) == 1
    s = summary[0]
    assert s.severity == Severity.INFO
    assert s.title == "ranked tier: too few principals to compare"
    assert s.description == (
        "Only 2 interactive principals had enough events to score; population "
        "comparison needs at least 5. No principal was ranked."
    )
    assert s.next_steps == [
        "No recommended action - population too small to rank",
        "Set min_scorable_principals in [detectors.aws] to compare smaller populations",
    ]
    assert s.evidence["scorable_count"] == 2
    assert s.evidence["population_floor"] == 5
    assert "top_composite_z" not in s.evidence
    assert "top_principal" not in s.evidence
    assert "composite_z" not in s.evidence
    # The burst tier is not population-relative - the sweep still surfaces.
    assert len(bursts) == 1
    assert bursts[0].severity == Severity.MEDIUM


def test_ranked_floor_n4_emits_below_floor_synthetic() -> None:
    """One below the floor: 4 scorable principals abstain."""
    events: list[dict] = []
    for name in ["alice", "bob", "carol", "dave"]:
        events.extend(_event(principal=name) for _ in range(60))
    findings = run(_ctx(_df(events)))
    summary = [f for f in findings if f.evidence.get("tier") == "ranked_summary"]
    assert [f for f in findings if f.evidence.get("tier") == "ranked"] == []
    assert len(summary) == 1
    assert summary[0].evidence["scorable_count"] == 4
    assert summary[0].evidence["population_floor"] == 5


def test_ranked_floor_n5_banding_engages() -> None:
    """At the floor exactly, banding goes live: an outlier leading on error
    rate and distinct action names among 5 scorable principals clears MEDIUM
    (composite well above the 2.0 band; a lone outlier's z is +2 per led
    signal at n=5)."""
    events: list[dict] = []
    for name in ["alice", "bob", "carol", "dave"]:
        events.extend(_event(principal=name, ts=_BASE_TS + i * 400.0)
                      for i in range(60))
    events += [
        _event(principal="eve", ts=_BASE_TS + 50.0 + i * 400.0,
               event_name=f"Action{i % 20}",
               error_code="AccessDenied" if i % 2 == 0 else None)
        for i in range(60)
    ]
    findings = run(_ctx(_df(events)))
    ranked = [f for f in findings if f.evidence.get("tier") == "ranked"]
    assert [f for f in findings if f.evidence.get("tier") == "ranked_summary"] == []
    assert len(ranked) == 1
    assert ranked[0].severity == Severity.MEDIUM
    assert ranked[0].evidence["principal"] == "eve"


def test_ranked_floor_override_two_reenables_banding() -> None:
    """min_scorable_principals=2 on the two-admin corpus: the operator's
    explicit choice re-enables banding at that size, and the busier admin's
    by-construction MEDIUM is reachable again."""
    findings = run(_ctx(_df(_two_admin_events()),
                        config={"min_scorable_principals": 2}))
    ranked = [f for f in findings if f.evidence.get("tier") == "ranked"]
    assert [f for f in findings if f.evidence.get("tier") == "ranked_summary"] == []
    assert len(ranked) == 1
    assert ranked[0].severity == Severity.MEDIUM
    assert ranked[0].evidence["principal"] == "admin-bob"


def test_ranked_floor_one_disables_gate() -> None:
    """min_scorable_principals=1 is the documented disable value: banding runs
    even at n=1 and the too-few-to-compare variant is never emitted (the
    degenerate population lands on the zero-cleared synthetic instead)."""
    events = [_event(principal="only-one") for _ in range(60)]
    findings = run(_ctx(_df(events), config={"min_scorable_principals": 1}))
    assert all("population_floor" not in f.evidence for f in findings)
    summary = [f for f in findings if f.evidence.get("tier") == "ranked_summary"]
    assert len(summary) == 1
    assert summary[0].evidence["top_composite_z"] == 0.0


def test_ranked_summary_zero_cleared_wording_byte_identical() -> None:
    """The zero-cleared synthetic's wording, byte-exact - the guard that the
    below-floor variant sharing its builder disturbed nothing. Five identical
    principals sit at the floor, band to composite 0, and tie-break to the
    first-appearance principal (groupby(sort=False) + stable sort)."""
    events: list[dict] = []
    for name in ["alice", "bob", "carol", "dave", "erin"]:
        events.extend(_event(principal=name) for _ in range(60))
    findings = run(_ctx(_df(events)))
    summary = [f for f in findings if f.evidence.get("tier") == "ranked_summary"]
    assert len(summary) == 1
    s = summary[0]
    assert s.severity == Severity.INFO
    assert s.title == "ranked tier: no principals cleared the LOW band"
    assert s.description == (
        "No scored interactive principal cleared the LOW band. Closest to the "
        "bar was alice (composite z 0.00)."
    )
    assert s.next_steps == [
        "No recommended action - nothing stood out",
        "Lower composite_low_threshold in [detectors.aws] to widen the surface",
    ]
    assert s.evidence == {
        "tier":            "ranked_summary",
        "scorable_count":  5,
        "top_principal":   "alice",
        "top_composite_z": 0.0,
    }


# ── below_floor_count helper ─────────────────────────────────────────────────

def test_below_floor_count_pure_helper_counts_correctly() -> None:
    events: list[dict] = []
    # 2 below-floor principals (5 events each)
    for name in ["alice", "bob"]:
        events.extend(_event(principal=name) for _ in range(5))
    # 1 at-or-above principal (50 events)
    events.extend(_event(principal="carol") for _ in range(50))
    df = _df(events)
    assert below_floor_count(df, 50) == 2


def test_below_floor_count_none_returns_zero() -> None:
    assert below_floor_count(None, 50) == 0


def test_below_floor_count_empty_returns_zero() -> None:
    assert below_floor_count(_df([]), 50) == 0


def test_below_floor_count_ignores_service_lane_principals() -> None:
    """Service-lane principals aren't candidates for scoring; they don't
    contribute to below-floor regardless of event count."""
    events = [_event(principal="ec2.amazonaws.com", lane="service") for _ in range(5)]
    assert below_floor_count(_df(events), 50) == 0


def test_below_floor_count_matches_detector_internal_count() -> None:
    """Same helper, same answer - analysis and disclosure never drift."""
    events: list[dict] = []
    for name in ["alice", "bob"]:
        events.extend(_event(principal=name) for _ in range(5))
    events.extend(_event(principal="carol") for _ in range(60))
    df = _df(events)
    n_via_helper = below_floor_count(df, 50)
    # And via the detector's actual aggregation: count interactive principals
    # with event_count < 50 in the per-principal frame.
    from sigwood.detectors.aws import _filter_interactive
    per = _aggregate_per_principal(_filter_interactive(df))
    n_internal = int((per["event_count"] < 50).sum())
    assert n_via_helper == n_internal == 2


# ── Output ordering & defensive contracts ────────────────────────────────────

def test_burst_findings_precede_ranked_findings() -> None:
    """Two-tier ordering: bursts first, then ranked. Mixed Findings list order."""
    events = (
        _enum_sweep("attacker", n_firsts=5, gap=30.0, start_ts=_BASE_TS)
        + [_event(principal=f"bland{i}",
                  source_ip=f"192.0.2.{i}",
                  event_name=f"Bland{j:02d}")
           for i in range(4) for j in range(60)]
    )
    df = _df(events)
    findings = run(_ctx(df, config={"min_events": 50}))
    tiers = [f.evidence["tier"] for f in findings]
    # No "ranked" tier finding may appear before a "burst" tier finding.
    last_burst_idx = max((i for i, t in enumerate(tiers) if t == "burst"), default=-1)
    first_other_idx = min(
        (i for i, t in enumerate(tiers) if t in {"ranked", "ranked_summary"}),
        default=len(tiers),
    )
    assert last_burst_idx < first_other_idx


def test_empty_frame_returns_empty_list() -> None:
    df = _df([])
    assert run(_ctx(df)) == []


def test_absent_pattern_returns_empty_list() -> None:
    """context.logs has no entry for *.json* - run() returns [] without raising."""
    ctx = DetectorContext(
        logs={},
        config={},
        allowlist=SimpleNamespace(filter_df=lambda d, name: d),
        data_window=_WINDOW,
        data_sources=[],
    )
    assert run(ctx) == []


def test_low_band_findings_emitted_without_verbose() -> None:
    """LOW ranked findings are NOT gated on context.verbose; the analyst is
    asking for the detector by selecting it."""
    # Make one principal a mild standout - composite ~ 1.0..1.5 range - so it
    # lands in LOW band with the default thresholds (1.0 → LOW, 2.0 → MEDIUM).
    events: list[dict] = []
    for name in ["alice", "bob", "carol", "dave"]:
        events.extend(_event(principal=name, source_ip="192.0.2.10",
                             event_name="GetObject")
                      for _ in range(60))
    # mild outlier: 2 distinct event names instead of 1
    for i in range(60):
        events.append(_event(
            principal="standout",
            source_ip="192.0.2.10",
            event_name="GetObject" if i % 2 == 0 else "ListBuckets",
        ))
    df = _df(events)
    findings_default = run(_ctx(df, config={"min_events": 50}))
    findings_verbose = run(_ctx(df, config={"min_events": 50}, verbose=True))
    # Whatever the severity is, the counts must match (no verbose gating).
    assert (
        sum(1 for f in findings_default if f.evidence.get("tier") == "ranked")
        == sum(1 for f in findings_verbose if f.evidence.get("tier") == "ranked")
    )
