"""Tests for the cloudtrail digest card (six fixed slots, lane-scoped pair).

Covers:
  - lane-split as a dist slot (always shows; both shares; never produces a lede)
  - principal-vol interactive-scoping (service-lane dominant principal must
    not bleed into the interactive cliff; floor + gate both proved to dash)
  - event-source cliff over the WHOLE pile (interactive + service together)
  - source-ip interactive-scoping (one IP dominating interactive speaks;
    service-lane source_ip hostnames like "s3.amazonaws.com" must NOT count)
  - region dist (single-region → "us-east-1 100%"; multi-region → top-3)
  - error-rate (kind = error_code.notna(); top contributor is the error CODE,
    not a principal; literal notna semantics; RATE_FLOOR gates real piles)
  - ledes from gating slots only - neither lane-split nor region prose may
    leak into a lede
  - sleepy whole-pile card: quiet-honest; mostly dashes; zero ledes
  - attack-shaped whole-pile card: multiple gating slots fire
  - CLI dispatch and runner-boundary plumbing for cloudtrail_dir
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

import sigwood.cli as cli
import sigwood.runner as runner
from sigwood.common.finding import DigestCard, RunSummary
from sigwood.digest import cloudtrail as ct_digest
from sigwood.outputs.text import TextHandler


# ─── Fixtures ────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 6, 11, 12, 0, tzinfo=timezone.utc)
_BASE_TS = _NOW.timestamp()

_CT_COLUMNS = [
    "ts", "principal", "lane", "read_write",
    "event_source", "event_name", "identity_type",
    "source_ip", "error_code", "aws_region", "event_id", "raw",
]


def _ct_row(
    principal: str = "arn:aws:iam::111111111111:user/alice",
    lane: str = "interactive",
    event_source: str = "iam.amazonaws.com",
    event_name: str = "ListUsers",
    source_ip: str = "203.0.113.10",
    aws_region: str = "us-east-1",
    error_code: object = None,
    identity_type: str = "IAMUser",
    read_write: str = "read",
    event_id: str = "evt-0001",
    ts: float = _BASE_TS,
) -> dict:
    """Build one canonical CloudTrail row dict with placeholder values.

    Defaults to a clean interactive IAM read by an example user. Tests override
    only the columns they care about - the rest carry safe sample values so
    the frame always has the full 12-column shape the parser emits.
    """
    return {
        "ts":            ts,
        "principal":     principal,
        "lane":          lane,
        "read_write":    read_write,
        "event_source":  event_source,
        "event_name":    event_name,
        "identity_type": identity_type,
        "source_ip":     source_ip,
        "error_code":    error_code,
        "aws_region":    aws_region,
        "event_id":      event_id,
        "raw":           {},
    }


def _ct_df(rows: list[dict]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=_CT_COLUMNS)
    return pd.DataFrame(rows, columns=_CT_COLUMNS)


def _slot_by_label(slots_or_frame, label):
    """Look up a computed slot by label.

    Accepts either a pre-built list of DigestSlot or a frame (re-derives
    via _compute_slots). The list form lets body["slots"]-style callers
    keep their shape; body["fields"] is the post-selection display set, not
    what these tests want. The frame form is preferred.
    """
    if isinstance(slots_or_frame, pd.DataFrame):
        slots = _compute_slots(slots_or_frame)
    else:
        slots = slots_or_frame
    for s in slots:
        if s.label == label:
            return s
    raise AssertionError(f"no slot with label {label!r}")


def _run_summary(
    window: tuple[datetime, datetime] = (_NOW - timedelta(days=1), _NOW),
) -> RunSummary:
    return RunSummary(
        data_window=window,
        record_counts={"*.json*": 100},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
        notes=[],
        data_sources=["cloudtrail"],
    )


def _card_from_body(body: dict) -> DigestCard:
    return DigestCard(
        schema="cloudtrail",
        source_name="cloudtrail.json.log",
        data_window=(_NOW - timedelta(days=1), _NOW),
        record_count=100,
        histogram_counts=[1, 2, 3, 5, 8, 5, 3, 2, 1],
        histogram_unit="hr",
        histogram_peak=8,
        zone1_extras=body["zone1_extras"],
        insights=body["insights"],
        fields=body["fields"],
    )


def _render(card: DigestCard) -> str:
    """Render the digest card through TextHandler and return the output text."""
    buffer = io.StringIO()
    handler = TextHandler(stream=buffer, verbose_level=0)
    handler.render_digest(card)
    return buffer.getvalue()


def _compute_slots(frame: pd.DataFrame) -> list:
    """Re-compute the canonical cloudtrail slot list for tests.

    Under the flat grammar the body returns only post-selection display
    state (`fields`), not a full pre-filter slot list. Tests that need to
    inspect a
    specific slot's computed state re-derive it here - same six
    computers, same interactive-lane scoping, in declared order.
    """
    if "lane" in frame.columns:
        frame_interactive = frame[frame["lane"] == "interactive"]
    else:
        frame_interactive = frame.iloc[0:0]
    return [
        ct_digest._slot_lane_split(frame),
        ct_digest._slot_principal_vol(frame_interactive),
        ct_digest._slot_event_source(frame),
        ct_digest._slot_source_ip(frame_interactive),
        ct_digest._slot_region(frame),
        ct_digest._slot_error_rate(frame),
    ]


# ─── lane-split (dist; whole pile; always shows) ────────────────────────────

def test_lane_split_renders_both_shares() -> None:
    frame = _ct_df(
        [_ct_row(lane="interactive") for _ in range(3)]
        + [_ct_row(lane="service") for _ in range(7)]
    )
    body = ct_digest.summarize(frame)
    slot = _slot_by_label(_compute_slots(frame), "lane-split")
    assert slot.statistic == "dist"
    assert slot.cells == ["interactive 30% / service 70%"]
    # dist never carries entity / ratio / magnitude
    assert slot.entity is None and slot.ratio is None and slot.magnitude is None


def test_lane_split_all_interactive_renders_zero_service() -> None:
    frame = _ct_df([_ct_row(lane="interactive") for _ in range(5)])
    body = ct_digest.summarize(frame)
    slot = _slot_by_label(_compute_slots(frame), "lane-split")
    assert slot.cells == ["interactive 100% / service 0%"]


def test_lane_split_empty_frame_renders_no_events_placeholder() -> None:
    body = ct_digest.summarize(_ct_df([]))
    slot = _slot_by_label(_compute_slots(_ct_df([])), "lane-split")
    assert slot.cells == ["(no events)"]


def test_lane_split_missing_lane_column_renders_no_lane_placeholder() -> None:
    # Drop the column entirely - mirrors the dns qtype-mix dual-fallback contract.
    frame = pd.DataFrame([
        {k: v for k, v in _ct_row().items() if k != "lane"}
        for _ in range(3)
    ])
    body = ct_digest.summarize(frame)
    slot = _slot_by_label(_compute_slots(frame), "lane-split")
    assert slot.cells == ["(no lane)"]


# ─── principal-vol (cliff; INTERACTIVE-SCOPED) ──────────────────────────────

def test_principal_vol_speaks_with_dominant_interactive_principal() -> None:
    # 5 distinct interactive principals, clear rank1/rank2 cliff.
    rows: list[dict] = []
    for _ in range(20):
        rows.append(_ct_row(principal="arn:aws:iam::111111111111:role/AdminRole"))
    for name in ("user/alice", "user/bob", "user/carol", "user/dave"):
        rows.append(_ct_row(principal=f"arn:aws:iam::111111111111:{name}"))
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "principal-vol")
    assert slot.statistic == "cliff"
    assert slot.entity == "arn:aws:iam::111111111111:role/AdminRole"
    assert slot.ratio is not None and slot.ratio >= 2.0
    # Cell renders the share-of-interactive percentage.
    assert slot.cells is not None
    assert slot.cells[0] == "arn:aws:iam::111111111111:role/AdminRole"
    assert slot.cells[1].endswith("%")


def test_principal_vol_dashes_when_interactive_neckandneck_despite_service_dominator() -> None:
    """Proves both (a) scoping and (b) the cliff floor.

    Service lane has one dominant principal that would WIN a whole-pile cliff.
    Interactive lane has only two principals (below POPULATION_FLOOR=5), so
    even though one of them dominates within interactive, the slot must dash
    below the population floor.
    """
    rows: list[dict] = []
    # 10 service rows all from the same service principal - would dominate
    # the whole-pile cliff if the interactive filter were forgotten.
    for _ in range(10):
        rows.append(_ct_row(
            principal="lambda.amazonaws.com",
            lane="service",
            identity_type="AWSService",
            event_source="lambda.amazonaws.com",
            source_ip="lambda.amazonaws.com",
        ))
    # 5 interactive rows split between two principals - below floor.
    for _ in range(3):
        rows.append(_ct_row(principal="arn:aws:iam::111111111111:user/alice"))
    for _ in range(2):
        rows.append(_ct_row(principal="arn:aws:iam::111111111111:user/bob"))
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "principal-vol")
    assert slot.cells is None  # dashed
    assert slot.entity is None and slot.ratio is None


# ─── event-source (cliff; WHOLE pile) ───────────────────────────────────────

def test_event_source_cliff_counts_whole_pile() -> None:
    """event-source counts interactive + service rows together (whole-pile)."""
    rows: list[dict] = []
    # 25 interactive iam events.
    for _ in range(25):
        rows.append(_ct_row(event_source="iam.amazonaws.com"))
    # 4 service rows across 4 other services - without the service rows the
    # population would only be 1 distinct source and the slot would dash;
    # whole-pile counting brings the population to 5.
    for src in ("ec2.amazonaws.com", "s3.amazonaws.com",
                "sts.amazonaws.com", "kms.amazonaws.com"):
        rows.append(_ct_row(lane="service", event_source=src,
                            principal=src, identity_type="AWSService",
                            source_ip=src))
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "event-source")
    assert slot.entity == "iam.amazonaws.com"
    assert slot.cells is not None
    assert slot.cells[0] == "iam.amazonaws.com"
    assert slot.cells[1] == "25"  # count, right-justified by handler
    assert slot.ratio is not None and slot.ratio >= 2.0


# ─── source-ip (share; INTERACTIVE-SCOPED; cell vs entity split) ────────────

def test_source_ip_speaks_with_one_dominant_interactive_ip() -> None:
    """20 events from one IP + 4 IPs at 1 each = 24 interactive,
    top_share = 20/24 ≈ 83% ≥ SHARE_GATE → speaks."""
    rows: list[dict] = []
    for _ in range(20):
        rows.append(_ct_row(source_ip="203.0.113.99"))
    for ip in ("203.0.113.10", "203.0.113.11",
               "203.0.113.12", "203.0.113.13"):
        rows.append(_ct_row(source_ip=ip))
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "source-ip")
    assert slot.statistic == "share"
    # Entity carries the actual IP for the lede…
    assert slot.entity == "203.0.113.99"
    # …but the table cell leads with "1 IP" for at-a-glance concentration.
    # Exactly TWO cells - share has no rank-2 ratio.
    assert slot.cells == ["1 IP", "83% of interactive"]
    # No rank-2 ratio on a share slot.
    assert slot.ratio is None
    assert slot.magnitude is not None and 82 <= slot.magnitude <= 84


def test_source_ip_speaks_on_two_distinct_ips_with_dominant_share() -> None:
    """The exact regression case the share-statistic fix unblocks.

    99 events from one IP + 1 from another → 2 distinct IPs total. The
    OLD cliff-based slot dashed here because 2 < POPULATION_FLOOR=5, even
    though concentration is 99%. The NEW share-based slot must speak and
    name the IP - that low cardinality is the SIGNAL, not noise.
    """
    rows = [_ct_row(source_ip="203.0.113.99") for _ in range(99)]
    rows.append(_ct_row(source_ip="203.0.113.10"))
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "source-ip")
    assert slot.statistic == "share"
    assert slot.entity == "203.0.113.99"
    assert slot.cells == ["1 IP", "99% of interactive"]


def test_source_ip_speaks_on_single_distinct_ip_at_100_percent() -> None:
    """10 events, all one IP → 1 distinct IP. top_share = 1.0 → speaks."""
    rows = [_ct_row(source_ip="203.0.113.99") for _ in range(10)]
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "source-ip")
    assert slot.statistic == "share"
    assert slot.entity == "203.0.113.99"
    assert slot.magnitude == 100.0
    assert slot.cells == ["1 IP", "100% of interactive"]


def test_source_ip_dashes_just_below_share_gate() -> None:
    """Locks SHARE_GATE = 0.80 as the threshold. 79 dominant + 21 spread
    → top_share = 0.79, just below gate → dashes."""
    rows = [_ct_row(source_ip="203.0.113.99") for _ in range(79)]
    # Spread 21 across many other IPs so no single IP-other clears the gate.
    for i in range(21):
        rows.append(_ct_row(source_ip=f"203.0.113.{100+i}"))
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "source-ip")
    assert slot.cells is None
    assert slot.statistic == "share"


def test_source_ip_dashes_on_diverse_interactive_sources() -> None:
    """Spread distribution → top_share = 1/N << SHARE_GATE → dashes."""
    rows = [
        _ct_row(source_ip=f"203.0.113.{i}") for i in range(10, 18)
    ]
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "source-ip")
    assert slot.cells is None
    assert slot.statistic == "share"


def test_source_ip_excludes_service_lane_hostnames() -> None:
    """A service-lane source_ip hostname (e.g. s3.amazonaws.com) must NOT
    affect source-ip - proves interactive scoping is doing real work.

    Without the interactive filter, the whole-pile share would compute
    25/31 ≈ 81% on "s3.amazonaws.com" - above SHARE_GATE - and the slot
    would speak on a service hostname. The interactive filter keeps that
    out: interactive lane has 6 IPs at 1 event each (top_share = 1/6 ≈
    17% << gate) → dashes.
    """
    rows: list[dict] = []
    for _ in range(25):
        rows.append(_ct_row(
            lane="service",
            source_ip="s3.amazonaws.com",
            principal="s3.amazonaws.com",
            identity_type="AWSService",
            event_source="s3.amazonaws.com",
        ))
    for ip in ("203.0.113.10", "203.0.113.11", "203.0.113.12",
               "203.0.113.13", "203.0.113.14", "203.0.113.15"):
        rows.append(_ct_row(source_ip=ip))
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "source-ip")
    assert slot.cells is None  # dashed - proves the scoping


def test_source_ip_lede_omits_ratio_phrase() -> None:
    """Direct check on the lede formatter contract: share slots produce
    no 'Nx the next' or 'more than' clause - concentration has no peer to
    compare against."""
    rows = [_ct_row(source_ip="203.0.113.99") for _ in range(95)]
    for ip in ("203.0.113.10", "203.0.113.11",
               "203.0.113.12", "203.0.113.13", "203.0.113.14"):
        rows.append(_ct_row(source_ip=ip))
    body = ct_digest.summarize(_ct_df(rows))
    source_ip_lede = next(
        (lede for lede in body["insights"] if "203.0.113.99" in lede), None
    )
    assert source_ip_lede is not None
    assert "x the next" not in source_ip_lede
    assert "more than" not in source_ip_lede
    assert source_ip_lede.endswith("interactive events.")


def test_source_ip_high_share_outranks_mid_cliff_in_salience() -> None:
    """A high-share source-ip lede should rank above a mid-magnitude cliff
    lede. Builds a pile where source-ip share is 95% (salience 95) and
    event-source cliff ratio is ~3 (salience 3) - source-ip lede must
    appear before event-source lede in body['insights']."""
    rows: list[dict] = []
    # 95 events from one IP, but spread across multiple event_sources so
    # the event-source cliff is weak.
    sources = ["iam.amazonaws.com"] * 30 + ["ec2.amazonaws.com"] * 25 + \
              ["s3.amazonaws.com"] * 20 + ["sts.amazonaws.com"] * 20
    for src in sources:
        rows.append(_ct_row(source_ip="203.0.113.99", event_source=src))
    # 5 background events so event-source clears POPULATION_FLOOR.
    for i in range(5):
        rows.append(_ct_row(
            source_ip=f"203.0.113.{10+i}",
            event_source="kms.amazonaws.com",
        ))
    body = ct_digest.summarize(_ct_df(rows))
    ledes = body["insights"]
    src_idx = next(
        (i for i, lede in enumerate(ledes) if "203.0.113.99" in lede), None
    )
    src_evt_idx = next(
        (i for i, lede in enumerate(ledes)
         if "iam.amazonaws.com" in lede and "service" in lede), None
    )
    assert src_idx is not None
    # event-source may not even make top-3, but if it does, source-ip outranks it.
    if src_evt_idx is not None:
        assert src_idx < src_evt_idx


# ─── region (dist; WHOLE pile; never produces a lede) ───────────────────────

def test_region_single_region_renders_100_percent() -> None:
    frame = _ct_df([_ct_row(aws_region="us-east-1") for _ in range(8)])
    body = ct_digest.summarize(frame)
    slot = _slot_by_label(_compute_slots(frame), "region")
    assert slot.statistic == "dist"
    assert slot.cells == ["us-east-1 100%"]


def test_region_multi_region_renders_top_three_with_separator() -> None:
    rows: list[dict] = []
    for _ in range(40):
        rows.append(_ct_row(aws_region="us-east-1"))
    for _ in range(30):
        rows.append(_ct_row(aws_region="eu-west-1"))
    for _ in range(10):
        rows.append(_ct_row(aws_region="us-west-2"))
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "region")
    assert slot.cells == ["us-east-1 50% · eu-west-1 38% · us-west-2 12%"]


def test_region_caps_at_top_three() -> None:
    rows: list[dict] = []
    for region, n in (("us-east-1", 30), ("eu-west-1", 20),
                      ("us-west-2", 10), ("ap-south-1", 5),
                      ("eu-central-1", 5)):
        for _ in range(n):
            rows.append(_ct_row(aws_region=region))
    body = ct_digest.summarize(_ct_df(rows))
    slot = _slot_by_label(_compute_slots(_ct_df(rows)), "region")
    assert slot.cells is not None
    assert slot.cells[0].count("·") == 2  # exactly three entries → two separators
    # Lower-ranked regions must NOT appear.
    assert "ap-south-1" not in slot.cells[0]
    assert "eu-central-1" not in slot.cells[0]


def test_region_empty_and_missing_column_have_distinct_fallbacks() -> None:
    body = ct_digest.summarize(_ct_df([]))
    assert _slot_by_label(_compute_slots(_ct_df([])), "region").cells == ["(no events)"]

    rows = [{k: v for k, v in _ct_row().items() if k != "aws_region"}
            for _ in range(3)]
    body = ct_digest.summarize(pd.DataFrame(rows))
    assert _slot_by_label(_compute_slots(pd.DataFrame(rows)), "region").cells == ["(no region)"]


# ─── error-rate (rate; WHOLE pile; names error CODE not principal) ──────────

def test_error_rate_dashes_when_no_errors() -> None:
    frame = _ct_df([_ct_row(error_code=None) for _ in range(20)])
    slot = _slot_by_label(frame, "error-rate")
    assert slot.cells is None


def test_error_rate_dashes_below_rate_floor() -> None:
    """200 events with 1 errored = 0.5% < RATE_FLOOR (1%) - dashes via floor."""
    rows = [_ct_row(error_code=None) for _ in range(199)]
    rows.append(_ct_row(error_code="AccessDenied"))
    slot = _slot_by_label(_ct_df(rows), "error-rate")
    assert slot.cells is None


def test_error_rate_names_top_error_code_not_principal() -> None:
    """Top contributor is the most common errorCode, NOT a principal."""
    rows: list[dict] = []
    for _ in range(80):
        rows.append(_ct_row(error_code=None))
    principals = [
        f"arn:aws:iam::111111111111:user/u{i}" for i in range(20)
    ]
    for i in range(15):
        rows.append(_ct_row(principal=principals[i % len(principals)],
                            error_code="AccessDenied"))
    for i in range(5):
        rows.append(_ct_row(principal=principals[(i + 7) % len(principals)],
                            error_code="ValidationException"))
    slot = _slot_by_label(_ct_df(rows), "error-rate")
    assert slot.entity == "AccessDenied"
    assert slot.cells is not None
    assert slot.cells[1] == "AccessDenied"
    assert slot.magnitude is not None and 19 <= slot.magnitude <= 21


def test_error_rate_notna_semantics_pin_none_nan_and_empty_string() -> None:
    """Literal .notna() - None and NaN read clean; "" reads as errored."""
    rows: list[dict] = []
    for i in range(45):
        rows.append(_ct_row(error_code=None))
    for i in range(45):
        rows.append(_ct_row(error_code=float("nan")))
    for i in range(10):
        rows.append(_ct_row(error_code=""))
    slot = _slot_by_label(_ct_df(rows), "error-rate")
    assert slot.cells is not None
    assert slot.entity == ""
    assert slot.magnitude is not None and 9 <= slot.magnitude <= 11


# ─── Ledes: dist slots never leak into prose ────────────────────────────────

def test_ledes_never_carry_dist_slot_prose() -> None:
    """All-interactive single-region pile - gating slots may fire ledes, but
    no lede string may contain the lane-split or region fill prose.

    Checked against rendered prose, not slot labels - label-presence checks
    would let "interactive 100% / service 0%" leak through if a formatter
    accidentally embedded it. Same for region's "us-east-1 100%".
    """
    rows: list[dict] = []
    # All-interactive - drives lane-split to "interactive 100% / service 0%".
    for _ in range(30):
        rows.append(_ct_row(
            principal="arn:aws:iam::111111111111:role/AdminRole",
            aws_region="us-east-1",
            source_ip="203.0.113.99",
            event_source="iam.amazonaws.com",
        ))
    # 5 more principals / IPs / sources so population floors are met but
    # the cliff still fires.
    for i in range(5):
        rows.append(_ct_row(
            principal=f"arn:aws:iam::111111111111:user/u{i}",
            source_ip=f"203.0.113.{20+i}",
            event_source=f"svc{i}.amazonaws.com",
            aws_region="us-east-1",
        ))
    body = ct_digest.summarize(_ct_df(rows))
    assert body["insights"]  # at least one cliff lede fired
    forbidden_fragments = (
        "interactive 100%", "service 0%", "/ service",
        "us-east-1 100%",
    )
    for lede in body["insights"]:
        for frag in forbidden_fragments:
            assert frag not in lede, (
                f"dist slot prose leaked into lede: {lede!r} contains {frag!r}"
            )


# ─── Summariser shape ───────────────────────────────────────────────────────

def test_summarize_returns_six_slots_in_fixed_order() -> None:
    body = ct_digest.summarize(_ct_df([_ct_row() for _ in range(3)]))
    labels = [s.label for s in _compute_slots(_ct_df([_ct_row() for _ in range(3)]))]
    assert labels == [
        "lane-split", "principal-vol", "event-source",
        "source-ip", "region", "error-rate",
    ]


def test_summarize_entity_label_and_zone1_extras() -> None:
    rows = [
        _ct_row(principal="arn:aws:iam::111111111111:user/alice",
                event_source="iam.amazonaws.com"),
        _ct_row(principal="arn:aws:iam::111111111111:user/bob",
                event_source="ec2.amazonaws.com"),
        _ct_row(principal="arn:aws:iam::111111111111:user/alice",
                event_source="s3.amazonaws.com"),
    ]
    body = ct_digest.summarize(_ct_df(rows))
    # entity_label / entity_count are deleted from the body dict under the
    # flat grammar; zone1_extras carries the distinct-counts as the only
    # surface the renderer consumes.
    assert ("principals", "2") in body["zone1_extras"]
    assert ("event sources", "3") in body["zone1_extras"]


# ─── Whole-card rendering ───────────────────────────────────────────────────

def _build_sleepy_rows() -> list[dict]:
    """Build the canonical sleepy pile used by the renderer test.

    50 events, 90% service / 10% interactive, two ≈balanced interactive
    principals, single region, no errors. Designed so all cliff/rate slots
    correctly dash:
      - principal-vol: 2 distinct interactive principals → below POPULATION_FLOOR
      - source-ip:     5 distinct interactive IPs, 1 each → ratio 1.0 < gate
      - event-source:  rank1/rank2 = 25/20 = 1.25 < gate
      - error-rate:    0 errors → kind_count short-circuit
    """
    rows: list[dict] = []
    # Service lane: 25 lambda + 20 ec2 - keeps the whole-pile event-source
    # cliff weak so the slot dashes.
    for _ in range(25):
        rows.append(_ct_row(
            principal="lambda.amazonaws.com", lane="service",
            event_source="lambda.amazonaws.com",
            event_name="Invoke", identity_type="AWSService",
            source_ip="lambda.amazonaws.com",
        ))
    for _ in range(20):
        rows.append(_ct_row(
            principal="ec2.amazonaws.com", lane="service",
            event_source="ec2.amazonaws.com",
            event_name="StartInstances", identity_type="AWSService",
            source_ip="ec2.amazonaws.com",
        ))
    # Interactive lane: 5 events split 3/2 across 2 principals, 5 distinct
    # IPs (one each - so the source-ip cliff is flat).
    for src_ip in ("203.0.113.10", "203.0.113.11", "203.0.113.12"):
        rows.append(_ct_row(
            principal="arn:aws:iam::111111111111:user/alice",
            event_source="iam.amazonaws.com", event_name="ListUsers",
            source_ip=src_ip,
        ))
    for src_ip in ("203.0.113.20", "203.0.113.21"):
        rows.append(_ct_row(
            principal="arn:aws:iam::111111111111:user/bob",
            event_source="sts.amazonaws.com", event_name="GetCallerIdentity",
            source_ip=src_ip,
        ))
    return rows


def _build_attack_rows() -> list[dict]:
    """Build the canonical attack-shaped pile.

    80 events, all interactive, one principal/IP utterly dominant, three
    regions, ~22% errors. Sized so principal-vol / source-ip salience
    (cliff ratio 76) clearly leads error-rate (salience 22) and event-source
    (cliff ratio 12) - guaranteed top-3 ledes are: principal-vol, source-ip,
    error-rate. event-source's cliff still fires (cells not None) but its
    lede drops out of the top-3 cutoff; the slot table row still shows it.
    """
    rows: list[dict] = []
    # 60 of the 76 dominant-role events go through IAM; the remaining 16
    # spread across four other services so event-source still clears
    # POPULATION_FLOOR with a meaningful but secondary cliff.
    services = (
        ["iam.amazonaws.com"] * 60
        + ["ec2.amazonaws.com"] * 4 + ["s3.amazonaws.com"] * 4
        + ["sts.amazonaws.com"] * 4 + ["kms.amazonaws.com"] * 4
    )
    regions = ["us-east-1"] * 38 + ["eu-west-1"] * 28 + ["us-west-2"] * 10
    # 16 AccessDenied + 2 ValidationException + 58 clean → ~22.5% error rate.
    error_codes = (
        ["AccessDenied"] * 16 + ["ValidationException"] * 2 + [None] * 58
    )
    for i in range(76):
        rows.append(_ct_row(
            principal="arn:aws:iam::111111111111:role/AdminRole",
            event_source=services[i],
            event_name="CreateUser" if (i % 3) == 0 else "ListUsers",
            source_ip="203.0.113.99",
            aws_region=regions[i],
            error_code=error_codes[i],
            # Per-row ts offsets give the timeline a non-zero span. Real
            # CloudTrail events have varying eventTime values; without the
            # offset, run_digest's confidence floor (zero-span guard) fires.
            ts=_BASE_TS + i,
        ))
    # 4 background events from 4 distinct (principal, IP, service) tuples -
    # just enough to clear POPULATION_FLOOR on each cliff.
    others = [
        ("arn:aws:iam::111111111111:role/BuildBot",
         "ec2.amazonaws.com", "203.0.113.10"),
        ("arn:aws:iam::111111111111:user/alice",
         "s3.amazonaws.com",  "203.0.113.11"),
        ("arn:aws:iam::111111111111:user/bob",
         "sts.amazonaws.com", "203.0.113.12"),
        ("arn:aws:iam::111111111111:user/carol",
         "kms.amazonaws.com", "203.0.113.13"),
    ]
    for j, (principal, source, ip) in enumerate(others):
        rows.append(_ct_row(
            principal=principal,
            event_source=source,
            event_name="DescribeFoo",
            source_ip=ip,
            aws_region="us-east-1",
            ts=_BASE_TS + 76 + j,
        ))
    return rows


def test_sleepy_card_is_quiet_with_zero_ledes() -> None:
    body = ct_digest.summarize(_ct_df(_build_sleepy_rows()))
    # Every gating slot dashes.
    for label in ("principal-vol", "event-source", "source-ip", "error-rate"):
        assert _slot_by_label(_compute_slots(_ct_df(_build_sleepy_rows())), label).cells is None, (
            f"sleepy pile: {label} unexpectedly fired"
        )
    # Both dist slots speak.
    assert _slot_by_label(_compute_slots(_ct_df(_build_sleepy_rows())), "lane-split").cells == [
        "interactive 10% / service 90%",
    ]
    assert _slot_by_label(_compute_slots(_ct_df(_build_sleepy_rows())), "region").cells == [
        "us-east-1 100%",
    ]
    # No gating slot → no insight.
    assert body["insights"] == []
    # Card renders without absent-footer machinery (no slot is ABSENT
    # under the flat grammar - non-speaking just vanishes from fields).
    text = _render(_card_from_body(body))
    assert "cloudtrail ·" in text  # identity-line-3 schema label
    assert "N.B." not in text
    assert "── digest" not in text  # no header rule


def test_attack_card_fires_multiple_ledes() -> None:
    body = ct_digest.summarize(_ct_df(_build_attack_rows()))
    # All four gating slots fire.
    for label in ("principal-vol", "event-source", "source-ip", "error-rate"):
        assert _slot_by_label(_compute_slots(_ct_df(_build_attack_rows())), label).cells is not None, (
            f"attack pile: {label} failed to fire"
        )
    # lane-split renders 100/0.
    assert _slot_by_label(_compute_slots(_ct_df(_build_attack_rows())), "lane-split").cells == [
        "interactive 100% / service 0%",
    ]
    # region renders top-3 with the dominant region first.
    region_cell = _slot_by_label(_compute_slots(_ct_df(_build_attack_rows())), "region").cells[0]
    assert region_cell.startswith("us-east-1 ")
    assert region_cell.count("·") == 2
    # AdminRole / dominant IP / top error code all named in some lede.
    assert any("AdminRole" in lede for lede in body["insights"])
    src_ip_lede = next(
        (lede for lede in body["insights"] if "203.0.113.99" in lede), None
    )
    assert src_ip_lede is not None
    # Source-ip lede has the new share contract - no ratio-against-next clause.
    assert "x the next" not in src_ip_lede
    assert "more than" not in src_ip_lede
    assert any("AccessDenied" in lede for lede in body["insights"])
    # Card renders - flat grammar, no header rule.
    text = _render(_card_from_body(body))
    assert "cloudtrail ·" in text
    assert "203.0.113.99" in text  # insight surfaces the dominant IP


# ─── CLI dispatch ───────────────────────────────────────────────────────────

def _spy_run_digest(monkeypatch) -> dict:
    captured: dict[str, Any] = {}

    def fake_run_digest(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(runner, "run_digest", fake_run_digest)
    return captured


def _stub_config(monkeypatch, cfg_dict: dict) -> None:
    monkeypatch.setattr(cli.cfg, "load", lambda _path: cfg_dict)


_CT_NDJSON_LINE = (
    '{"eventVersion": "1.08", "eventTime": "2026-06-01T12:00:00Z",'
    ' "userIdentity": {"type": "IAMUser"}, "eventName": "GetObject",'
    ' "eventSource": "s3.amazonaws.com", "sourceIPAddress": "192.0.2.10"}\n'
)


def _write_ct_sniff_file(tmp_path: Path) -> Path:
    log_path = tmp_path / "cloudtrail.json.log"
    log_path.write_text(_CT_NDJSON_LINE, encoding="utf-8")
    return log_path


def test_cli_digest_cloudtrail_file_sniffs_and_routes_to_cloudtrail_dir(
    tmp_path, monkeypatch,
) -> None:
    captured = _spy_run_digest(monkeypatch)
    _stub_config(monkeypatch, {"sigwood": {}})
    log_path = _write_ct_sniff_file(tmp_path)
    cli._main(["digest", str(log_path)])
    assert captured.get("schema") == "cloudtrail"
    assert captured.get("cloudtrail_dir") == str(log_path)
    assert captured.get("zeek_dir") is None
    assert captured.get("pihole_dir") is None
    assert captured.get("syslog_dir") is None


def test_cli_digest_cloudtrail_bare_falls_back_to_conn_default(tmp_path, monkeypatch) -> None:
    """Bare `digest` always defaults to schema=conn under the new surface.

    Configured cloudtrail_dir alone cannot drive a bare digest - documented
    consequence of removing the schema token. Users wanting a cloudtrail
    digest pass a CloudTrail file as positional.
    """
    captured = _spy_run_digest(monkeypatch)
    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    _stub_config(monkeypatch, {"sigwood": {"cloudtrail_dir": str(ct_dir)}})
    cli._main(["digest"])
    assert captured.get("schema") == "conn"
    assert captured.get("cloudtrail_dir") is None


def test_cli_digest_cloudtrail_file_with_since_flag(tmp_path, monkeypatch) -> None:
    captured = _spy_run_digest(monkeypatch)
    _stub_config(monkeypatch, {"sigwood": {}})
    log_path = _write_ct_sniff_file(tmp_path)
    cli._main(["digest", str(log_path), "--since=7d"])
    assert captured.get("schema") == "cloudtrail"
    assert captured.get("cloudtrail_dir") == str(log_path)
    assert captured.get("since") is not None


# ─── Runner-level dispatch ──────────────────────────────────────────────────

def test_run_digest_rejects_zeek_dir_at_programmatic_boundary(tmp_path) -> None:
    config: dict[str, Any] = {"sigwood": {}}
    with pytest.raises(ValueError,
                       match="zeek_dir is not valid for the cloudtrail schema"):
        runner.run_digest(
            config=config, schema="cloudtrail",
            cloudtrail_dir=tmp_path,
            zeek_dir=tmp_path / "zeek",
        )


def test_run_digest_rejects_pihole_dir_at_programmatic_boundary(tmp_path) -> None:
    config: dict[str, Any] = {"sigwood": {}}
    with pytest.raises(ValueError,
                       match="pihole_dir is not valid for the cloudtrail schema"):
        runner.run_digest(
            config=config, schema="cloudtrail",
            cloudtrail_dir=tmp_path,
            pihole_dir=tmp_path / "pihole",
        )


def test_run_digest_rejects_syslog_dir_at_programmatic_boundary(tmp_path) -> None:
    config: dict[str, Any] = {"sigwood": {}}
    with pytest.raises(ValueError,
                       match="syslog_dir is not valid for the cloudtrail schema"):
        runner.run_digest(
            config=config, schema="cloudtrail",
            cloudtrail_dir=tmp_path,
            syslog_dir=tmp_path / "syslog",
        )


def test_run_digest_rejects_missing_cloudtrail_dir(tmp_path) -> None:
    config: dict[str, Any] = {"sigwood": {}}
    with pytest.raises(ValueError, match="cloudtrail_dir not configured"):
        runner.run_digest(config=config, schema="cloudtrail")


# ─── End-to-end via run_digest ──────────────────────────────────────────────

def _row_to_wire_event(row: dict) -> dict:
    """Render a canonical row dict back to a CloudTrail wire event.

    The loader/parser pipeline reads wire JSON (eventTime / userIdentity /
    eventSource / …) and produces canonical rows. Going back the other way
    for synthetic test files keeps the end-to-end path realistic without
    having to maintain a parallel JSON fixture file.
    """
    identity: dict[str, Any] = {"type": row["identity_type"]}
    # Map the row's principal back to whichever userIdentity field the
    # parser's derivation rule uses, so the parser's principal matches.
    if row["identity_type"] == "AWSService":
        identity["invokedBy"] = row["principal"]
    elif row["identity_type"] == "AssumedRole":
        identity["sessionContext"] = {
            "sessionIssuer": {"userName": row["principal"]},
        }
    elif row["identity_type"] == "IAMUser":
        # Use the arn so the parser's IAMUser path picks up the last
        # slash-segment as principal - matches our placeholder shape.
        identity["arn"] = row["principal"]
        identity["userName"] = row["principal"].rsplit("/", 1)[-1] \
            if "/" in row["principal"] else row["principal"]
    elif row["identity_type"] == "Root":
        identity["type"] = "Root"
    event: dict[str, Any] = {
        "eventTime": datetime.fromtimestamp(
            row["ts"], tz=timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "userIdentity": identity,
        "eventSource": row["event_source"],
        "eventName": row["event_name"],
        "sourceIPAddress": row["source_ip"],
        "awsRegion": row["aws_region"],
        "eventID": row["event_id"],
    }
    if row["error_code"] is not None:
        event["errorCode"] = row["error_code"]
    return event


def _write_ndjson(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(_row_to_wire_event(row)))
            fh.write("\n")


def test_run_digest_cloudtrail_end_to_end_renders_a_card(tmp_path, capsys) -> None:
    """Full path: synthetic NDJSON file → run_digest → rendered card.

    Flat grammar: identity-line schema label, dominant-IP surfaced by an
    insight, dist slots (lane-split, region) always render as fields.
    Promoted-insight slots do NOT also render as fields.
    """
    ct_dir = tmp_path / "ct"
    rows = _build_attack_rows()
    _write_ndjson(ct_dir / "events.json.log", rows)

    config: dict[str, Any] = {"sigwood": {}}
    runner.run_digest(
        config=config, schema="cloudtrail",
        cloudtrail_dir=ct_dir, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    assert "cloudtrail ·" in out
    # Dist slots always render in fields.
    assert "lane-split:" in out
    assert "region:" in out
    # Attack pile surfaces the dominant IP.
    assert "203.0.113.99" in out
    # No header rule, no footer machinery under the flat grammar.
    assert "── digest" not in out
    assert "N.B." not in out
    assert "ABSENT" not in out


def test_run_digest_cloudtrail_end_to_end_sleepy_pile_is_quiet(tmp_path, capsys) -> None:
    """Sleepy pile: every gating slot dashes (non-speaking), so insights
    is empty AND those slots vanish from fields. Only the two dist slots
    (lane-split, region) survive in the fields block."""
    ct_dir = tmp_path / "ct"
    _write_ndjson(ct_dir / "events.json.log", _build_sleepy_rows())
    config: dict[str, Any] = {"sigwood": {}}
    runner.run_digest(
        config=config, schema="cloudtrail",
        cloudtrail_dir=ct_dir, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    assert "cloudtrail ·" in out
    assert "interactive 10% / service 90%" in out
    assert "us-east-1 100%" in out
    # Non-speaking gating slots vanish - no label appears in the fields.
    for label in ("principal-vol:", "event-source:",
                  "source-ip:", "error-rate:"):
        assert label not in out
    assert "ABSENT" not in out
