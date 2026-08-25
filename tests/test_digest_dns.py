"""Tests for the dns digest card (fidelity-aware, six fixed slots).

Covers:
  - tail statistic: population floor, gate, median-zero guard, owner attribution
  - rate statistic: presence floor, top-contributor attribution, 1%-pile fact reporting
  - dist statistic (qtype-mix): always shows; numeric → mnemonic mapping; two fallbacks
  - feed-keyed slot selection: Zeek vs Pi-hole; absent-with-reason routing
  - renderer integration: footer routing, mixed-width row alignment, cell ordering
  - ledes: cross-statistic salience; qtype-mix never produces a lede; cap phrasing
  - CLI dispatch: sniff-driven schema routing, Zeek vs Pi-hole origin split
"""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pandas as pd
import pytest

import sigwood.cli as cli
import sigwood.runner as runner
from sigwood.common import loader
from sigwood.common.loader.types import _PIHOLE_COLUMNS as _LOADER_PIHOLE_COLUMNS
from sigwood.common.finding import DigestCard, DigestSlot, RunSummary
from sigwood.digest import dns as dns_digest
from sigwood.outputs.text import TextHandler


# ─── Fixtures ────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 6, 11, 12, 0, tzinfo=timezone.utc)
_BASE_TS = _NOW.timestamp()

_ZEEK_DNS_COLUMNS = [
    "ts", "src", "query", "rtt", "ttl", "rcode", "answer", "tc", "qtype",
]
_PIHOLE_COLUMNS = [
    "ts", "src", "query", "event_type", "qtype", "host",
]


def _zeek_dns_row(
    src: str = "192.0.2.10",
    query: str = "example.com",
    qtype: int = 1,
    rcode: int = 0,
    ts: float = _BASE_TS,
    rtt: float | None = 0.05,
    ttl: float | None = 300.0,
    answer=None,
    tc: int | None = 0,
) -> dict:
    return {
        "ts":     ts,
        "src":    src,
        "query":  query,
        "rtt":    rtt,
        "ttl":    ttl,
        "rcode":  rcode,
        "answer": answer if answer is not None else ["198.51.100.1"],
        "tc":     tc,
        "qtype":  qtype,
    }


def _zeek_dns_df(rows: list[dict]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=_ZEEK_DNS_COLUMNS)
    return pd.DataFrame(rows, columns=_ZEEK_DNS_COLUMNS)


def _pihole_row(
    src: str = "192.0.2.10",
    query: str = "example.com",
    event_type: str = "query",
    qtype: str = "A",
    ts: float = _BASE_TS,
) -> dict:
    return {
        "ts":          ts,
        "src":         src,
        "query":       query,
        "event_type":  event_type,
        "qtype":       qtype,
        "host":        None,
    }


def _pihole_df(rows: list[dict]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=_PIHOLE_COLUMNS)
    return pd.DataFrame(rows, columns=_PIHOLE_COLUMNS)


def _run_summary(window: tuple[datetime, datetime] = (_NOW - timedelta(days=1), _NOW)) -> RunSummary:
    return RunSummary(
        data_window=window,
        record_counts={"dns*.log*": 100},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
        notes=[],
        data_sources=["zeek_dns"],
    )


def _card_from_body(body: dict, schema: str = "dns") -> DigestCard:
    """Build a DigestCard from a summariser body dict, plus spine ambient."""
    return DigestCard(
        schema=schema,
        source_name="dns.log",
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
    handler = TextHandler(stream=io.StringIO())
    handler.render_digest(card)
    return handler._stream.getvalue()


# ─── tail statistic ──────────────────────────────────────────────────────────

def test_tail_dashes_below_population_floor() -> None:
    # 3 queries - below POPULATION_FLOOR=5 even with a wide spread
    rows = [_zeek_dns_row(src="192.0.2.10", query="a"),
            _zeek_dns_row(src="192.0.2.11", query="b" * 100),
            _zeek_dns_row(src="192.0.2.12", query="c" * 50)]
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_query_length(df)
    assert slot.cells is None


def test_tail_dashes_below_gate() -> None:
    # 6 queries with max=4 and median=2 → ratio 2.0 < TAIL_GATE=3.0
    queries = ["aa", "aa", "aa", "aaa", "aaaa", "aa"]  # lens 2,2,2,3,4,2 median=2 max=4
    rows = [_zeek_dns_row(src=f"192.0.2.{i+10}", query=q) for i, q in enumerate(queries)]
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_query_length(df)
    assert slot.cells is None


def test_tail_dashes_when_median_is_zero() -> None:
    # All empty queries → median length 0 → dash, no exception
    rows = [_zeek_dns_row(src=f"192.0.2.{i+10}", query="") for i in range(6)]
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_query_length(df)
    assert slot.cells is None


def test_tail_names_owner_when_speaking() -> None:
    # 5 short + 1 long (tunnelling-shape hex label under example.com)
    short_rows = [_zeek_dns_row(src=f"192.0.2.{i+10}", query="example.com") for i in range(5)]
    long_query = "deadbeefcafef00d12345678abcdef0123456789.example.com"  # 53 chars
    long_row = _zeek_dns_row(src="192.0.2.99", query=long_query)
    df = _zeek_dns_df(short_rows + [long_row])
    slot = dns_digest._slot_query_length(df)
    assert slot.cells is not None
    # Owner named in slot.entity
    assert slot.entity == "192.0.2.99"


def test_query_length_cell_order_is_maxlen_ratio_owner() -> None:
    """Cell order per brief: [maxlen, ratio, owner]. Locks against an
    accidental [owner, maxlen, ratio] swap."""
    short_rows = [_zeek_dns_row(src=f"192.0.2.{i+10}", query="example.com") for i in range(5)]
    # Long query: 53 chars, median = len("example.com") = 11 → ratio ~4.8
    long_query = "abcdef1234567890abcdef1234567890abcdef.example.com"  # 50 chars
    long_row = _zeek_dns_row(src="192.0.2.99", query=long_query)
    df = _zeek_dns_df(short_rows + [long_row])
    slot = dns_digest._slot_query_length(df)
    assert slot.cells is not None
    assert len(slot.cells) == 3
    # Cell 0: maxlen
    assert slot.cells[0].endswith(" chars")
    assert slot.cells[0].split()[0] == str(len(long_query))
    # Cell 1: ratio
    assert slot.cells[1].endswith("x")
    # Cell 2: owner
    assert slot.cells[2] == "192.0.2.99"


def test_query_length_lede_leads_with_owner() -> None:
    # Build a slot whose tail speaks and check the lede prose order
    short_rows = [_zeek_dns_row(src=f"192.0.2.{i+10}", query="example.com") for i in range(5)]
    long_row = _zeek_dns_row(src="192.0.2.99",
                             query="abcdef1234567890abcdef1234567890.example.com")
    df = _zeek_dns_df(short_rows + [long_row])
    body = dns_digest.summarize(df, feed="zeek")
    matching = [l for l in body["insights"] if "192.0.2.99" in l]
    assert matching, f"expected a lede mentioning 192.0.2.99; got {body['insights']}"
    assert matching[0].startswith("192.0.2.99"), (
        "query-length lede must lead with the owner"
    )


def test_query_length_lede_says_nothing_about_intent() -> None:
    """The lede surfaces shape as fact; no evaluative adjectives."""
    short_rows = [_zeek_dns_row(src=f"192.0.2.{i+10}", query="example.com") for i in range(5)]
    long_row = _zeek_dns_row(src="192.0.2.99",
                             query="deadbeef.cafe.feed.face.example.com")
    df = _zeek_dns_df(short_rows + [long_row])
    body = dns_digest.summarize(df, feed="zeek")
    matching = [l for l in body["insights"] if "192.0.2.99" in l]
    assert matching
    lede_text = " ".join(matching).lower()
    for forbidden in ("tunnel", "suspicious", "bad", "concerning", "malicious", "attack"):
        assert forbidden not in lede_text, (
            f"query-length lede must not contain {forbidden!r}; got: {lede_text}"
        )


# ─── rate statistic ──────────────────────────────────────────────────────────

def test_rate_dashes_below_floor() -> None:
    # 1000 rows, 5 NXDOMAIN → fraction 0.005 < RATE_FLOOR=0.01 → dash
    rows = []
    for i in range(995):
        rows.append(_zeek_dns_row(src=f"192.0.2.{i % 250 + 10}", rcode=0))
    for i in range(5):
        rows.append(_zeek_dns_row(src=f"192.0.2.{i + 200}", rcode=3))
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_nxdomain_rate(df, feed="zeek")
    assert slot.cells is None


def test_rate_dashes_below_population_floor() -> None:
    # 3 rows total → below POPULATION_FLOOR=5 → dash even if all are NXDOMAIN
    rows = [_zeek_dns_row(src=f"192.0.2.{i+10}", rcode=3) for i in range(3)]
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_nxdomain_rate(df, feed="zeek")
    assert slot.cells is None


def test_rate_one_percent_pile_reports_one_percent_with_no_judgment() -> None:
    """A 1% NXDOMAIN pile is reported as FACT (1%) with no badness adjective."""
    rows = [_zeek_dns_row(src="192.0.2.10", rcode=0) for _ in range(99)]
    rows.append(_zeek_dns_row(src="192.0.2.99", query="bogus.example.com", rcode=3))
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    slot = dns_digest._slot_nxdomain_rate(df, feed="zeek")
    assert slot.cells is not None
    assert slot.cells[0] == "1% failed"
    # Lede must report 1% and contain no judgmental language
    lede = next(l for l in body["insights"] if "NXDOMAIN" in l)
    assert "1%" in lede
    lede_lower = lede.lower()
    for forbidden in ("suspicious", "bad", "concerning", "dangerous", "malicious", "attack"):
        assert forbidden not in lede_lower, (
            f"rate lede must not contain {forbidden!r}; got: {lede}"
        )


def test_rate_attributes_top_contributor() -> None:
    """Top contributor = the src with the most NXDOMAIN rows."""
    # 80 normal rows
    rows = [_zeek_dns_row(src="192.0.2.20", rcode=0) for _ in range(80)]
    # 5 NXDOMAIN from .99 (top), 2 each from .10 and .11
    rows.extend([_zeek_dns_row(src="192.0.2.99", rcode=3) for _ in range(5)])
    rows.extend([_zeek_dns_row(src="192.0.2.10", rcode=3) for _ in range(2)])
    rows.extend([_zeek_dns_row(src="192.0.2.11", rcode=3) for _ in range(2)])
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_nxdomain_rate(df, feed="zeek")
    assert slot.cells is not None
    assert slot.entity == "192.0.2.99"  # top contributor named


def test_block_rate_uses_event_type_set() -> None:
    """gravity_blocked AND regex_blocked counted; other event types not."""
    # 90 'query' rows + 5 gravity_blocked + 5 regex_blocked = 100, 10% blocked
    rows = [_pihole_row(query="example.com", event_type="query") for _ in range(90)]
    rows.extend([_pihole_row(query="ads.example.net",
                              event_type="gravity_blocked") for _ in range(5)])
    rows.extend([_pihole_row(query="ads.example.net",
                              event_type="regex_blocked") for _ in range(5)])
    df = _pihole_df(rows)
    slot = dns_digest._slot_block_rate(df, feed="pihole")
    assert slot.cells is not None
    # 10% blocked → cells[0] = "10% blocked"
    assert slot.cells[0] == "10% blocked"
    # Top blocked domain = ads.example.net (both flavors of block count)
    assert slot.entity == "ads.example.net"


# ─── qtype-mix / dist statistic ─────────────────────────────────────────────

def test_qtype_mix_always_shows_single_type() -> None:
    """Single-category pile still shows - that IS the characterisation."""
    rows = [_zeek_dns_row(qtype=1) for _ in range(10)]
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_qtype_mix(df, feed="zeek")
    assert slot.cells == ["A 100%"]


def test_qtype_mix_top_three_by_share() -> None:
    """Mixed Zeek codes → top-3 rendered with share% each."""
    rows = []
    rows.extend([_zeek_dns_row(qtype=1) for _ in range(50)])    # A 50%
    rows.extend([_zeek_dns_row(qtype=28) for _ in range(30)])   # AAAA 30%
    rows.extend([_zeek_dns_row(qtype=65) for _ in range(15)])   # HTTPS 15%
    rows.extend([_zeek_dns_row(qtype=15) for _ in range(5)])    # MX 5% (drops off top-3)
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_qtype_mix(df, feed="zeek")
    assert slot.cells is not None
    mix = slot.cells[0]
    # Top-3 in share order: A, AAAA, HTTPS
    assert "A 50%" in mix
    assert "AAAA 30%" in mix
    assert "HTTPS 15%" in mix
    # MX is below top-3 but its share is disclosed.
    assert "MX" not in mix
    assert mix == "A 50% · AAAA 30% · HTTPS 15% · (other) 5%"


def test_qtype_mix_discloses_a_positive_remainder_below_one_percent() -> None:
    rows = (
        [_zeek_dns_row(qtype=1) for _ in range(1000)]
        + [_zeek_dns_row(qtype=28) for _ in range(500)]
        + [_zeek_dns_row(qtype=65) for _ in range(100)]
        + [_zeek_dns_row(qtype=15)]
    )
    slot = dns_digest._slot_qtype_mix(_zeek_dns_df(rows), feed="zeek")
    assert slot.cells is not None
    assert slot.cells[0].endswith(" · (other) <1%")


def test_qtype_mix_without_hidden_categories_is_byte_identical() -> None:
    rows = (
        [_zeek_dns_row(qtype=1) for _ in range(5)]
        + [_zeek_dns_row(qtype=28) for _ in range(3)]
        + [_zeek_dns_row(qtype=65) for _ in range(2)]
    )
    slot = dns_digest._slot_qtype_mix(_zeek_dns_df(rows), feed="zeek")
    assert slot.cells == ["A 50% · AAAA 30% · HTTPS 20%"]


def test_qtype_mix_maps_unmapped_code_to_TYPE_N() -> None:
    """Zeek qtype with no mnemonic mapping renders as TYPE<n>."""
    rows = [_zeek_dns_row(qtype=99) for _ in range(10)]  # 99 not in mnemonic dict
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_qtype_mix(df, feed="zeek")
    assert slot.cells == ["TYPE99 100%"]


def test_qtype_mix_uses_pihole_mnemonics_asis() -> None:
    """Pi-hole qtype is already a string mnemonic - use as-is."""
    rows = [_pihole_row(qtype="AAAA") for _ in range(10)]
    df = _pihole_df(rows)
    slot = dns_digest._slot_qtype_mix(df, feed="pihole")
    assert slot.cells == ["AAAA 100%"]


def test_qtype_mix_tolerates_missing_qtype_column_without_crash() -> None:
    """Defensive: missing qtype column → '(no qtype)' fallback, no KeyError."""
    df = pd.DataFrame([
        {"ts": 1.0, "src": "192.0.2.10", "query": "example.com"},
        {"ts": 2.0, "src": "192.0.2.11", "query": "example.net"},
    ])
    # qtype column absent
    assert "qtype" not in df.columns
    slot = dns_digest._slot_qtype_mix(df, feed="zeek")
    assert slot.cells == ["(no qtype)"]


def test_qtype_mix_empty_frame_renders_no_queries_fallback() -> None:
    """qtype column present but all-NaN → '(no queries)' (distinct from (no qtype))."""
    df = _zeek_dns_df([_zeek_dns_row(qtype=None) for _ in range(3)])
    # Replace qtype with NaN
    df["qtype"] = pd.NA
    slot = dns_digest._slot_qtype_mix(df, feed="zeek")
    assert slot.cells == ["(no queries)"]


# ─── Feed-keyed slot selection ──────────────────────────────────────────────
#
# Old grammar marked feed-uncomputable slots ABSENT WITH REASON and footered
# them under N.B. lines. The flat grammar deletes that whole concept - a
# feed-uncomputable slot is just non-speaking, and the summariser filters
# non-speaking slots out of `fields`. So the slot vanishes from the rendered
# card entirely.


def test_zeek_nxdomain_rate_slot_is_speakable_or_dashed() -> None:
    """On Zeek, nxdomain-rate is computable: the slot either speaks or
    is non-speaking (dashed-equivalent) - never the deleted ABSENT state."""
    df = _zeek_dns_df([_zeek_dns_row() for _ in range(10)])
    slot = dns_digest._slot_nxdomain_rate(df, feed="zeek")
    assert slot.statistic == "rate"
    # Bi-state slot: either speaking (cells set) or not (cells None).
    # No ABSENT reason field exists anymore.
    assert hasattr(slot, "cells")


def test_zeek_block_rate_is_non_speaking_and_vanishes_from_fields() -> None:
    """block-rate is Pi-hole-only. On the Zeek feed it returns a
    non-speaking slot that the summariser filters out of `fields` - no
    ABSENT, no N.B., the slot is simply absent from the rendered card."""
    df = _zeek_dns_df([_zeek_dns_row() for _ in range(10)])
    slot = dns_digest._slot_block_rate(df, feed="zeek")
    assert slot.cells is None  # non-speaking
    body = dns_digest.summarize(df, feed="zeek")
    assert not any(s.label == "block-rate" for s in body["fields"])


def test_pihole_block_rate_slot_is_speakable_or_dashed() -> None:
    """On Pi-hole, block-rate is computable: speaks or stays non-speaking."""
    df = _pihole_df([_pihole_row() for _ in range(10)])
    slot = dns_digest._slot_block_rate(df, feed="pihole")
    assert slot.statistic == "rate"


def test_pihole_nxdomain_rate_is_non_speaking_and_vanishes_from_fields() -> None:
    """nxdomain-rate is Zeek-only (needs rcode). On the Pi-hole feed it
    returns a non-speaking slot; vanishes from the rendered card."""
    df = _pihole_df([_pihole_row() for _ in range(10)])
    slot = dns_digest._slot_nxdomain_rate(df, feed="pihole")
    assert slot.cells is None
    body = dns_digest.summarize(df, feed="pihole")
    assert not any(s.label == "nxdomain-rate" for s in body["fields"])


def test_summarize_slot_computer_call_order_both_feeds() -> None:
    """The six slot computers always run in fixed order; the rendered
    `fields` contains only the speaking, non-promoted subset."""
    expected_order = ["client-volume", "domain-volume", "query-length",
                      "qtype-mix", "nxdomain-rate", "block-rate"]
    # Sanity: the six private slot computers exist.
    for label in expected_order:
        attr = "_slot_" + label.replace("-", "_")
        assert hasattr(dns_digest, attr), f"missing computer: {attr}"


# ─── Renderer integration ───────────────────────────────────────────────────

def test_render_dns_card_omits_feed_uncomputable_slots_entirely() -> None:
    """On the Zeek feed, block-rate is non-speaking → vanishes from
    `fields` → never reaches the renderer. No ABSENT, no N.B., no
    'block-rate:' label anywhere in the output."""
    body = dns_digest.summarize(
        _zeek_dns_df([_zeek_dns_row() for _ in range(3)]), feed="zeek",
    )
    card = _card_from_body(body)
    output = _render(card)
    assert "block-rate:" not in output
    assert "ABSENT" not in output
    assert "N.B." not in output


def test_render_dns_card_non_speaking_slots_vanish_not_dashed() -> None:
    """Under the flat grammar, non-speaking slots vanish from `fields`
    entirely - there is no dash placeholder. A card with a non-speaking
    client-volume simply omits that label from the rendered output."""
    # Tiny frame: client-volume cliff dashes (population below floor).
    rows = [_zeek_dns_row(src="192.0.2.10")]
    df = _zeek_dns_df(rows)
    slot = dns_digest._slot_client_volume(df)
    assert slot.cells is None  # confirms non-speaking on this input
    body = dns_digest.summarize(df, feed="zeek")
    card = _card_from_body(body)
    output = _render(card)
    assert "client-volume:" not in output
    assert "ABSENT" not in output


def test_render_dns_card_qtype_mix_renders_as_single_field_row() -> None:
    """Dist slot always shows up in fields - single label/value row,
    flush-left, with the cell content joined by 2 spaces (one cell here)."""
    rows = []
    for i in range(50):
        rows.append(_zeek_dns_row(query="dominant.example.com", qtype=1))
    for i in range(5):
        rows.append(_zeek_dns_row(query=f"q{i}.example.com", qtype=28))
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    card = _card_from_body(body)
    output = _render(card)
    qm_line = next(l for l in output.splitlines() if l.startswith("qtype-mix:"))
    # Dist cell content present; no shared-column padding now (each row
    # renders its own label-aligned value column).
    assert "A " in qm_line  # the A 50% / A NN% segment


def test_render_dns_card_rate_slot_either_promotes_or_appears_in_fields() -> None:
    """nxdomain-rate is a rate slot: at 1% it may either become an
    insight (top-3 by salience) OR remain in fields. The renderer never
    paints it as ABSENT or dashed under the flat grammar - exactly one
    surfacing must exist."""
    rows = [_zeek_dns_row(src="192.0.2.10", rcode=0) for _ in range(99)]
    rows.append(_zeek_dns_row(src="192.0.2.99", rcode=3))
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    card = _card_from_body(body)
    output = _render(card)
    # The 192.0.2.99 + NXDOMAIN signal appears exactly once - as an
    # insight sentence OR as a fields-block row. Never as a dash, never
    # as ABSENT.
    import re
    assert "ABSENT" not in output
    assert "NXDOMAIN" in output or "nxdomain-rate:" in output
    if "nxdomain-rate:" in output:
        nx_line = next(l for l in output.splitlines() if l.startswith("nxdomain-rate:"))
        assert re.search(r"nxdomain-rate:\s*\d+% failed\s+192\.0\.2\.99", nx_line), (
            f"nxdomain-rate row shape mismatch: {nx_line!r}"
    )


def test_render_dns_card_zeek_feed_shape_smoke() -> None:
    """Full Zeek card shape: zone-1 lines, histogram, table, footer note."""
    rows = [_zeek_dns_row(src=f"192.0.2.{i % 20 + 10}", query="example.com") for i in range(50)]
    rows.append(_zeek_dns_row(src="192.0.2.99", query="failure.example.com", rcode=3))
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    card = _card_from_body(body)
    output = _render(card)
    # Ambient lines (flush-left, no indent under flat grammar)
    assert "clients:" in output
    assert "domains:" in output
    # block-rate vanishes on the Zeek feed: non-speaking → filtered out
    # of `fields` → never rendered. No ABSENT label, no N.B. footer.
    assert "block-rate:" not in output
    assert "ABSENT" not in output
    assert "N.B." not in output


def test_render_dns_card_pihole_feed_shape_smoke() -> None:
    """Full Pi-hole card: block-rate populated (or promoted to an
    insight), nxdomain-rate vanishes (Zeek-only). No ABSENT, no footer."""
    rows = [_pihole_row(query="example.com", event_type="query") for _ in range(90)]
    rows.extend([_pihole_row(query="ads.example.net",
                              event_type="gravity_blocked") for _ in range(10)])
    df = _pihole_df(rows)
    body = dns_digest.summarize(df, feed="pihole")
    card = _card_from_body(body)
    output = _render(card)
    # nxdomain-rate vanishes on Pi-hole
    assert "nxdomain-rate:" not in output
    # block-rate either prints as an insight sentence OR appears in the
    # fields block (when not promoted). One of those must be present.
    assert "blocked" in output
    assert "ABSENT" not in output
    assert "N.B." not in output


# ─── Ledes ───────────────────────────────────────────────────────────────────

def test_ledes_silent_on_flat_pile() -> None:
    """No gating slot speaks → ledes is empty."""
    # 5 distinct clients, 5 distinct domains, all same-length queries, no NXDOMAIN
    rows = [_zeek_dns_row(src=f"192.0.2.{i+10}", query=f"d{i}.example.com",
                          qtype=1, rcode=0) for i in range(5)]
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    assert body["insights"] == []


def test_ledes_cross_statistic_salience_orders_rate_above_cliff() -> None:
    """Cliff with ratio 4 + rate at 50% (salience ~50) → rate lede first."""
    # 50% NXDOMAIN salience = 50.0 / 1.0 = 50 (since RATE_FLOOR*100 = 1)
    # client-volume cliff with ratio 4 has salience 4
    rows = []
    # Top src 192.0.2.99 issues 80; secondary srcs each 20 → cliff ratio 4
    for _ in range(80):
        rows.append(_zeek_dns_row(src="192.0.2.99", rcode=3))  # also NXDOMAIN
    for i in range(4):
        for _ in range(20):
            rows.append(_zeek_dns_row(src=f"192.0.2.{i+10}", rcode=0))
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    # Both speak: client-volume (ratio 4) and nxdomain-rate (50%)
    assert body["insights"], f"expected ledes; got: {body['insights']}"
    # nxdomain-rate salience ~50 outranks cliff salience 4 → first lede is the rate
    assert "NXDOMAIN" in body["insights"][0], (
        f"expected rate lede first; got: {body['insights']}"
    )


def test_qtype_mix_never_produces_a_lede() -> None:
    """Even though qtype-mix has rich content, no lede mentions its wording."""
    rows = [_zeek_dns_row(qtype=1) for _ in range(5)] + \
           [_zeek_dns_row(qtype=28) for _ in range(3)]
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    for lede in body["insights"]:
        assert "qtype-mix" not in lede
        # Match-rate style phrasing
        assert " %" not in lede or "% of queries" in lede or "% failed" in lede or "% blocked" in lede


def test_qtype_mix_never_produces_a_lede_even_when_visually_dominant() -> None:
    """qtype-mix never contributes to ledes, even when no gating slot speaks
    and qtype-mix is the most visually prominent row in the card."""
    # 5 distinct clients, equal share - all gating slots dash
    rows = []
    for i, qtype in enumerate([1, 28, 65, 15, 16]):
        rows.append(_zeek_dns_row(src=f"192.0.2.{i+10}",
                                   query=f"d{i}.example.com", qtype=qtype))
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    # qtype-mix is rendered (always shows in fields - dist statistic
    # never produces an insight), but insights themselves are empty.
    qtype_slot = next(s for s in body["fields"] if s.label == "qtype-mix")
    assert qtype_slot.cells is not None  # qtype-mix speaks visually
    assert body["insights"] == [], f"qtype-mix must not produce a lede; got: {body['insights']}"


def test_cliff_lede_uses_cap_phrasing_above_threshold() -> None:
    """Cliff ratio >= CLIFF_DISPLAY_CAP renders 'more than 50x' in lede prose."""
    # Top src issues 100, all others 1 each (5 others) → ratio 100
    rows = [_zeek_dns_row(src="192.0.2.99", query=f"q{i}.example.com")
            for i in range(100)]
    for i in range(5):
        rows.append(_zeek_dns_row(src=f"192.0.2.{i+10}", query=f"d{i}.example.com"))
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    # client-volume should speak with ratio 100; its lede should contain capped phrase
    matching = [l for l in body["insights"] if "192.0.2.99" in l and "issued" in l]
    assert matching, f"expected client-volume lede; got: {body['insights']}"
    assert "more than 50x" in matching[0]


def test_tail_lede_uses_cap_phrasing_above_threshold() -> None:
    """Tail ratio >= CLIFF_DISPLAY_CAP renders 'more than 50x' in lede prose."""
    # 5 short queries (len 1) + 1 huge (len 100) → ratio 100
    rows = [_zeek_dns_row(src=f"192.0.2.{i+10}", query="a") for i in range(5)]
    rows.append(_zeek_dns_row(src="192.0.2.99", query="a" * 100))
    df = _zeek_dns_df(rows)
    body = dns_digest.summarize(df, feed="zeek")
    matching = [l for l in body["insights"] if "192.0.2.99" in l and "character" in l]
    assert matching, f"expected query-length lede; got: {body['insights']}"
    assert "more than 50x" in matching[0]


# ─── CLI dispatch via sniff (no schema token) ───────────────────────────────

_ZEEK_DNS_NDJSON_LINE = (
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "query": "example.test"}\n'
)

_PIHOLE_LINE = (
    "Jun  1 12:00:00 piholehost dnsmasq[123]: query[A] example.test from 192.0.2.10\n"
)


def _spy_run_digest(monkeypatch) -> dict:
    """Replace runner.run_digest with a spy; return the captured kwargs dict."""
    captured: dict[str, Any] = {}

    def fake_run_digest(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(runner, "run_digest", fake_run_digest)
    return captured


def _stub_config(monkeypatch, cfg_dict: dict) -> None:
    monkeypatch.setattr(cli.cfg, "load", lambda _path: cfg_dict)


def test_cli_digest_zeek_dns_file_sniffs_to_dns_schema_zeek_origin(
    tmp_path, monkeypatch,
) -> None:
    """Zeek dns NDJSON file → schema=dns, routed to zeek_dir."""
    captured = _spy_run_digest(monkeypatch)
    _stub_config(monkeypatch, {"sigwood": {}})
    log_path = tmp_path / "dns.log"
    log_path.write_text(_ZEEK_DNS_NDJSON_LINE, encoding="utf-8")
    cli._main(["digest", str(log_path)])
    assert captured.get("schema") == "dns"
    assert captured.get("zeek_dir") == str(log_path)
    assert captured.get("pihole_dir") is None


def test_cli_digest_pihole_file_sniffs_to_dns_schema_pihole_origin(
    tmp_path, monkeypatch,
) -> None:
    """Pi-hole dnsmasq file → schema=dns, routed to pihole_dir."""
    captured = _spy_run_digest(monkeypatch)
    _stub_config(monkeypatch, {"sigwood": {}})
    log_path = tmp_path / "pihole.log"
    log_path.write_text(_PIHOLE_LINE, encoding="utf-8")
    cli._main(["digest", str(log_path)])
    assert captured.get("schema") == "dns"
    assert captured.get("pihole_dir") == str(log_path)
    assert captured.get("zeek_dir") is None


def test_run_digest_empty_pihole_frame_uses_canonical_columns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real digest loader selects a column-stable empty Pi-hole frame.

    ``DigestEmpty`` is the expected control signal; this test captures the
    frame immediately before that runner decision so its schema cannot drift
    from the parser/loader contract unnoticed.
    """
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text("", encoding="utf-8")

    observed: dict[str, list[str]] = {}
    real_load_required_logs = loader.load_required_logs

    def capture_empty_frame(*args, **kwargs):
        result = real_load_required_logs(*args, **kwargs)
        observed["columns"] = list(result.logs["pihole*.log*"].columns)
        return result

    monkeypatch.setattr(loader, "load_required_logs", capture_empty_frame)

    with pytest.raises(runner.DigestEmpty):
        runner.run_digest(
            config={"sigwood": {}}, pihole_dir=pihole_dir, schema="dns",
            load_all=True, skip_confirm=True,
        )

    assert observed["columns"] == _LOADER_PIHOLE_COLUMNS == _PIHOLE_COLUMNS


# ─── Single-file Zeek bypass - dns variant ─────────────────────────────────

_ZEEK_DNS_NDJSON_LINE_FOR_BYPASS = (
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "id.resp_h": "192.0.2.53",'
    ' "id.resp_p": 53, "proto": "udp", "query": "example.test",'
    ' "qtype": 1, "qclass": 1, "rcode": 0,'
    ' "answers": ["198.51.100.10"], "TTLs": [300.0]}\n'
)


def test_run_digest_date_prefixed_zeek_dns_renders_card_with_rows(
    tmp_path: Path, capsys,
) -> None:
    """Date-prefixed Zeek DNS NDJSON single file renders a DNS card with
    real rows. Companion to the conn variant in test_digest_conn.py -
    confirms the single-file Zeek bypass in run_digest covers the dns
    pattern (``dns*.log*``) as well as conn."""
    log_file = tmp_path / "2026-06-09.dns.log"
    # A handful of identical-shaped rows with distinct ts values so the
    # spine has something to bin AND the timeline has a non-zero span
    # (required by the ts-confidence guard in run_digest).
    import json as _json
    base = _json.loads(_ZEEK_DNS_NDJSON_LINE_FOR_BYPASS)
    lines = []
    for i in range(6):
        row = dict(base)
        row["ts"] = base["ts"] + i
        lines.append(_json.dumps(row) + "\n")
    log_file.write_text("".join(lines), encoding="utf-8")

    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    runner.run_digest(
        config=config, zeek_dir=log_file, schema="dns",
        load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    assert "(no events in window)" not in out
    assert "peak:" in out


def test_cli_digest_rejects_source_dir_flag_with_positional(
    tmp_path, monkeypatch,
) -> None:
    """--pihole-dir is not in digest's allowed set under the spec-driven
    parser, so passing it raises the wrong-verb error from the parser, not
    the positional-guard 'not valid alongside' message. Either way the
    combination is rejected up-front so silent override never happens."""
    _stub_config(monkeypatch, {"sigwood": {}})
    log_path = tmp_path / "dns.log"
    log_path.write_text(_ZEEK_DNS_NDJSON_LINE, encoding="utf-8")
    with pytest.raises(ValueError, match="--pihole-dir is not valid for digest"):
        cli._main(["digest", str(log_path), "--pihole-dir=/y"])


def test_cli_digest_dns_old_token_form_each_positional_is_a_path(
    monkeypatch, capsys,
) -> None:
    """`digest dns PATH` (Stage 3) - both `dns` and `PATH` are positionals
    that get sniffed independently; neither names an existing file, so each
    surfaces a "path not found" line and the run exits 1."""
    _stub_config(monkeypatch, {"sigwood": {}})
    import os as _os
    cwd = _os.getcwd()
    try:
        _os.chdir(_os.path.dirname(_os.path.abspath(__file__)))
        rc = cli._main(["digest", "dns", "/some/other/PATH"])
    finally:
        _os.chdir(cwd)
    captured = capsys.readouterr()
    assert captured.err.count("not found") == 2
    assert rc == 1


def test_cli_digest_processes_every_positional(tmp_path, monkeypatch) -> None:
    """`digest FILE EXTRA` (Stage 3) - every positional is digested; the
    Stage 2 "extras silently dropped" contract is replaced by fan-out."""
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        runner, "run_digest", lambda **kwargs: calls.append(kwargs),
    )
    _stub_config(monkeypatch, {"sigwood": {}})
    log_a = tmp_path / "dns_a.log"
    log_a.write_text(_ZEEK_DNS_NDJSON_LINE, encoding="utf-8")
    log_b = tmp_path / "dns_b.log"
    log_b.write_text(_ZEEK_DNS_NDJSON_LINE, encoding="utf-8")
    rc = cli._main(["digest", str(log_a), str(log_b)])
    assert rc == 0
    assert len(calls) == 2
    assert calls[0]["schema"] == "dns"
    assert calls[0]["zeek_dir"] == str(log_a)
    assert calls[1]["schema"] == "dns"
    assert calls[1]["zeek_dir"] == str(log_b)
