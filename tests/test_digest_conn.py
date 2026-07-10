"""Tests for the digest verb and the conn schema summariser.

Covers:
  - cliff statistic (gate, population floor, rank2=0)
  - the four conn slots (host involvement, internal/external endpoint rules)
  - histogram adaptive binning + axis label + empty-frame fallback
  - mechanical lede derivation (sorted by raw slot.ratio, never by parsing cells)
  - text renderer (order of zones, scale anchor, axis label)
  - allowlist non-invocation (architectural fork)
  - default-window paths for all three boundedness states
  - CLI dispatch and whitelist enforcement
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

import sigwood.runner as runner
from sigwood.common.display import default_window_advisory
from sigwood.common.finding import DigestCard, DigestSlot, RunSummary
from sigwood.digest import conn as conn_digest
from sigwood.digest import _stats
from sigwood.outputs.text import (
    TextHandler,
    _bar_glyph,
    _format_count,
    _render_histogram,
)


def _conn_insights_and_fields(slots: list[DigestSlot]) -> tuple[list[str], list[DigestSlot]]:
    """Adapter - exercises the new shared selection helper with conn's
    own formatter map. Equivalent to the deleted conn_digest._build_ledes."""
    return _stats.select_insights_and_fields(slots, conn_digest._INSIGHT_FORMATTERS)


# ─── Fixtures ────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 6, 11, 12, 0, tzinfo=timezone.utc)
_BASE_TS = _NOW.timestamp()


def _conn_row(
    src: str = "10.0.0.10",
    dst: str = "192.0.2.20",
    port: int = 443,
    proto: str = "tcp",
    ts: float = _BASE_TS,
    bytes_: float | None = 1000,
    conn_state: str | None = "SF",
    local_orig: bool | None = True,
) -> dict:
    """Build a single canonical conn row.

    Defaults to internal-source (RFC1918) → external-dst (RFC 5737), TCP/443,
    1000 originator bytes, local_orig=True. Override any column via kwargs.
    """
    return {
        "src":         src,
        "dst":         dst,
        "port":        port,
        "proto":       proto,
        "ts":          ts,
        "bytes":       bytes_,
        "conn_state":  conn_state,
        "local_orig":  local_orig,
    }


def _conn_df(rows: list[dict]) -> pd.DataFrame:
    """Build a canonical conn DataFrame from row dicts."""
    columns = ["src", "dst", "port", "proto", "ts", "bytes", "conn_state", "local_orig"]
    if not rows:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame(rows, columns=columns)


def _run_summary(window: tuple[datetime, datetime] = (_NOW - timedelta(days=1), _NOW)) -> RunSummary:
    return RunSummary(
        data_window=window,
        record_counts={"conn*.log*": 100},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
        notes=[],
        data_sources=["zeek_conn"],
    )


def _write_conn_ndjson(path: Path, rows: list[dict]) -> None:
    """Write conn rows as Zeek-shaped NDJSON (loader will normalise)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for row in rows:
        records.append({
            "ts":        row["ts"],
            "id.orig_h": row["src"],
            "id.resp_h": row["dst"],
            "id.resp_p": row["port"],
            "proto":     row["proto"],
            **({"orig_bytes": row["bytes"]} if row.get("bytes") is not None else {}),
            **({"conn_state": row["conn_state"]} if row.get("conn_state") is not None else {}),
            **({"local_orig": row["local_orig"]} if row.get("local_orig") is not None else {}),
        })
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


# ─── Cliff statistic ─────────────────────────────────────────────────────────

def test_cliff_dashes_below_population_floor() -> None:
    series = pd.Series([100, 10, 5], index=["a", "b", "c"]).sort_values(ascending=False)
    assert conn_digest._cliff(series) is None


def test_cliff_dashes_below_gate() -> None:
    series = pd.Series([15, 10, 9, 8, 7, 6], index=list("abcdef")).sort_values(ascending=False)
    assert conn_digest._cliff(series) is None  # 15 / 10 = 1.5 < 2.0


def test_cliff_names_rank1_when_speaking() -> None:
    series = pd.Series([40, 10, 9, 8, 7, 6], index=list("abcdef")).sort_values(ascending=False)
    result = conn_digest._cliff(series)
    assert result is not None
    entity, magnitude, ratio = result
    assert entity == "a"
    assert magnitude == 40.0
    assert ratio == pytest.approx(4.0)


def test_cliff_handles_rank2_zero() -> None:
    series = pd.Series([10, 0, 0, 0, 0], index=list("abcde")).sort_values(ascending=False)
    assert conn_digest._cliff(series) is None


# ─── conn-share semantics ────────────────────────────────────────────────────

def test_conn_share_counts_host_involvement_across_src_and_dst() -> None:
    # Host "10.0.0.50" appears only as dst; should still contribute to its
    # involvement count and to the distinct-host population.
    rows = [
        _conn_row(src="10.0.0.10", dst="10.0.0.50"),
        _conn_row(src="10.0.0.11", dst="10.0.0.50"),
        _conn_row(src="10.0.0.12", dst="10.0.0.50"),
        _conn_row(src="10.0.0.13", dst="10.0.0.50"),
        _conn_row(src="10.0.0.14", dst="10.0.0.50"),
    ]
    df = _conn_df(rows)
    slot = conn_digest._slot_conn_share(df)
    # 5 distinct srcs + the one common dst = 6 hosts → population floor met
    assert slot.cells is not None
    assert slot.entity == "10.0.0.50"
    # 5 involvements out of 5 rows = 100%
    assert slot.magnitude == pytest.approx(100.0)
    assert slot.ratio == pytest.approx(5.0)  # rank1=5, rank2=1 each


def test_conn_share_speaks_with_dominant_host() -> None:
    rows = [_conn_row(src="10.0.0.50", dst=f"192.0.2.{i}") for i in range(10)]
    rows.append(_conn_row(src="10.0.0.11", dst="192.0.2.11"))
    df = _conn_df(rows)
    slot = conn_digest._slot_conn_share(df)
    assert slot.cells is not None
    assert slot.entity == "10.0.0.50"
    assert slot.cells[0] == "10.0.0.50"
    assert "%" in slot.cells[1]
    assert slot.cells[2].endswith("x")
    # Raw cliff ratio carried for lede sorting
    assert slot.ratio is not None and slot.ratio >= 2.0


def test_conn_share_dashes_on_flat_pile() -> None:
    rows = [_conn_row(src=f"10.0.0.{i}", dst=f"192.0.2.{i}") for i in range(10, 15)]
    df = _conn_df(rows)
    slot = conn_digest._slot_conn_share(df)
    assert slot.cells is None
    assert slot.entity is None
    assert slot.magnitude is None
    assert slot.ratio is None


# ─── densest-tuple, fan-out ──────────────────────────────────────────────────

def test_densest_tuple_speaks_with_dominant_flow() -> None:
    rows = [_conn_row(src="10.0.0.10", dst="10.0.0.1", port=22) for _ in range(20)]
    for i in range(5):
        rows.append(_conn_row(src=f"10.0.0.{i+20}", dst="192.0.2.99", port=443))
    df = _conn_df(rows)
    slot = conn_digest._slot_densest_tuple(df)
    assert slot.cells is not None
    assert slot.entity == "10.0.0.10 → 10.0.0.1:22"
    assert slot.cells[0] == "10.0.0.10 → 10.0.0.1:22"


def test_fan_out_speaks_with_dominant_source() -> None:
    rows = [
        _conn_row(src="10.0.0.53", dst=f"192.0.2.{i}", port=53)
        for i in range(20)
    ]
    for i in range(5):
        rows.append(_conn_row(src=f"10.0.0.{i+100}", dst="198.51.100.1", port=80))
    df = _conn_df(rows)
    slot = conn_digest._slot_fan_out(df)
    assert slot.cells is not None
    assert slot.entity == "10.0.0.53:53"
    assert "dsts" in slot.cells[1]


# ─── byte-direction: internal/external endpoint rules ───────────────────────

def test_byte_direction_requires_internal_src_and_external_dst() -> None:
    # Mix of internal↔internal, external→internal, and only ONE genuinely
    # outbound flow group → population of 1 outbound dst → slot must dash
    # (population floor).
    rows = [
        _conn_row(src="10.0.0.10", dst="10.0.0.20", bytes_=10_000),  # int→int
        _conn_row(src="198.51.100.1", dst="10.0.0.10", bytes_=10_000, local_orig=False),  # ext→int
        _conn_row(src="10.0.0.10", dst="192.0.2.1", bytes_=10_000),  # int→ext
    ]
    df = _conn_df(rows)
    slot = conn_digest._slot_byte_direction(df)
    # Only 1 outbound destination → population floor (5) not met → dash.
    assert slot.cells is None


def test_byte_direction_uses_local_orig_when_present() -> None:
    # A public-looking src with local_orig=True must be treated as internal.
    # Six distinct external dsts; the 50k-byte one must dominate cliff.
    rows = [
        _conn_row(src="203.0.113.10", dst="192.0.2.50", local_orig=True, bytes_=50_000),
    ]
    for i in range(6):
        rows.append(_conn_row(src="203.0.113.10", dst=f"198.51.100.{i+1}",
                              local_orig=True, bytes_=1_000))
    df = _conn_df(rows)
    slot = conn_digest._slot_byte_direction(df)
    assert slot.cells is not None
    assert slot.entity == "192.0.2.50"


def test_byte_direction_local_orig_false_excludes_rfc1918_src() -> None:
    # local_orig=False overrides RFC1918 - src is treated as external, so the
    # 999_999-byte row to 192.0.2.50 is NOT outbound and must not dominate.
    # Six other outbound rows with varied bytes give a clear rank-1 elsewhere.
    rows = [
        _conn_row(src="10.0.0.10", dst="192.0.2.50",
                  local_orig=False, bytes_=999_999),
    ]
    for i, b in enumerate([10_000, 1_000, 500, 200, 100, 50]):
        rows.append(_conn_row(src="10.0.0.11", dst=f"198.51.100.{i+1}",
                              local_orig=True, bytes_=b))
    df = _conn_df(rows)
    slot = conn_digest._slot_byte_direction(df)
    assert slot.cells is not None
    assert slot.entity == "198.51.100.1"
    assert slot.entity != "192.0.2.50"


def test_byte_direction_falls_back_to_rfc1918_when_local_orig_nan() -> None:
    # local_orig missing → RFC1918(src) decides. RFC1918 src + external dst → outbound.
    # 50k-byte dst should dominate over six 1k-byte dsts. The 50k/1k = 50.0
    # ratio lands exactly on CLIFF_DISPLAY_CAP, so the rendered cell caps but
    # slot.ratio stays the raw float - locks the display/storage separation
    # at a realistic call site.
    rows = [
        _conn_row(src="10.0.0.10", dst="192.0.2.50", local_orig=None, bytes_=50_000),
    ]
    for i in range(6):
        rows.append(_conn_row(src="10.0.0.10", dst=f"198.51.100.{i+1}",
                              local_orig=None, bytes_=1_000))
    df = _conn_df(rows)
    slot = conn_digest._slot_byte_direction(df)
    assert slot.cells is not None
    assert slot.entity == "192.0.2.50"
    # Display-cap separation: raw ratio preserved, rendered cell capped
    assert slot.ratio == pytest.approx(50.0)
    assert slot.cells[2] == ">50x"


def test_byte_direction_treats_nan_bytes_as_zero() -> None:
    # NaN bytes contribute 0 - 192.0.2.50 has NaN bytes; the five varied-byte
    # outbound rows give a clear rank-1 elsewhere.
    rows = [
        _conn_row(src="10.0.0.10", dst="192.0.2.50", bytes_=None),
    ]
    for i, b in enumerate([50_000, 1_000, 500, 200, 100]):
        rows.append(_conn_row(src="10.0.0.10", dst=f"198.51.100.{i+1}", bytes_=b))
    df = _conn_df(rows)
    slot = conn_digest._slot_byte_direction(df)
    assert slot.cells is not None
    # 192.0.2.50 with NaN bytes (counted as 0) must NOT be rank-1
    assert slot.entity == "198.51.100.1"
    assert slot.entity != "192.0.2.50"


# ─── Zone-1 extras ───────────────────────────────────────────────────────────

def test_zone1_split_uses_rfc1918_per_host_not_local_orig() -> None:
    # 10.0.0.X appears only as dst (no local_orig for that endpoint) but is
    # RFC1918, so it must count as internal in the Zone-1 split.
    rows = [
        _conn_row(src="198.51.100.5", dst="10.0.0.50", local_orig=False),
    ]
    df = _conn_df(rows)
    body = conn_digest.summarize(df)
    # zone1_extras: first entry is the "hosts" combined line
    label, value = body["zone1_extras"][0]
    assert label == "hosts"
    # Both endpoints are visible; 10.0.0.50 must be classified internal.
    assert "1 internal" in value


def test_zone1_byte_totals_outbound_and_inbound() -> None:
    rows = [
        _conn_row(src="10.0.0.10", dst="192.0.2.1", bytes_=1000, local_orig=True),    # outbound
        _conn_row(src="198.51.100.5", dst="10.0.0.10", bytes_=500, local_orig=False),  # inbound
    ]
    df = _conn_df(rows)
    body = conn_digest.summarize(df)
    labels_to_values = dict(body["zone1_extras"])
    assert labels_to_values["outbound bytes"] == "1000 B"
    assert labels_to_values["inbound bytes"] == "500 B"


def _card_from_summary(df: pd.DataFrame) -> DigestCard:
    """Build a DigestCard from a conn frame via the REAL summariser, for the
    rendered-seam byte-slot tests (mirrors `_empty_card`'s field set)."""
    body = conn_digest.summarize(df)
    return DigestCard(
        schema="conn",
        source_name="conn.log",
        data_window=(_NOW - timedelta(days=1), _NOW),
        record_count=len(df),
        histogram_counts=[],
        histogram_unit="hr",
        histogram_peak=0,
        zone1_extras=body["zone1_extras"],
        insights=body["insights"],
        fields=body["fields"],
    )


def test_render_conn_no_bytes_column_says_no_byte_data() -> None:
    """A conn frame with NO `bytes` column renders one honest `bytes: no byte data`
    row at the user-visible seam - never the misleading `outbound/inbound bytes:
    0 B` (no byte data ≠ zero bytes)."""
    df = _conn_df([_conn_row(src="10.0.0.10", dst="192.0.2.1")]).drop(columns=["bytes"])
    rendered = _render_card(_card_from_summary(df))
    assert "bytes: no byte data" in rendered
    assert "outbound bytes" not in rendered
    assert "inbound bytes" not in rendered


def test_render_conn_all_zero_bytes_column_renders_zero_b() -> None:
    """A PRESENT all-zero `bytes` column is genuinely-zero traffic → the two
    outbound/inbound `0 B` rows are PRESERVED (absent-column vs all-zero kept
    separate). Alignment-tolerant: the ambient block pads labels to max width."""
    df = _conn_df([
        _conn_row(src="10.0.0.10", dst="192.0.2.1", bytes_=0, local_orig=True),
        _conn_row(src="198.51.100.5", dst="10.0.0.10", bytes_=0, local_orig=False),
    ])
    rendered = _render_card(_card_from_summary(df))
    assert "no byte data" not in rendered
    lines = rendered.splitlines()
    assert any(l.startswith("outbound bytes:") and l.endswith("0 B") for l in lines)
    assert any(l.startswith("inbound bytes:") and l.endswith("0 B") for l in lines)


# ─── Histogram ───────────────────────────────────────────────────────────────

def test_histogram_picks_hourly_for_short_span() -> None:
    start = datetime(2026, 6, 11, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(hours=24)
    ts = pd.Series([
        (start + timedelta(hours=h)).timestamp() for h in range(0, 24)
    ])
    counts, unit, peak = runner._compute_histogram(ts, (start, end))
    assert unit == "hr"
    assert len(counts) == 24
    assert peak == 1


def test_histogram_picks_daily_for_long_span() -> None:
    start = datetime(2026, 5, 1, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=30)
    ts = pd.Series([
        (start + timedelta(days=d, hours=12)).timestamp() for d in range(30)
    ])
    counts, unit, peak = runner._compute_histogram(ts, (start, end))
    assert unit == "day"
    assert len(counts) == 30
    assert peak == 1


def test_histogram_peak_reflects_max_bin() -> None:
    start = datetime(2026, 6, 11, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(hours=4)
    # Five events all in hour-1
    ts = pd.Series([
        (start + timedelta(hours=1, minutes=m)).timestamp() for m in (1, 2, 3, 4, 5)
    ])
    counts, _unit, peak = runner._compute_histogram(ts, (start, end))
    assert peak == 5
    assert counts[1] == 5


def test_histogram_zero_span_single_record_emits_one_bin() -> None:
    """A frame whose min-ts == max-ts (single event, or all events sharing one
    timestamp) must emit a one-bin histogram, not the no-events fallback.

    Regression for the zero-span defect: the prior implementation returned
    `[], "hr", 0` whenever start == end, silently discarding non-empty ts.
    """
    ts_value = datetime(2026, 6, 11, 12, 0, tzinfo=timezone.utc).timestamp()
    ts = pd.Series([ts_value, ts_value, ts_value])
    window_dt = datetime.fromtimestamp(ts_value, tz=timezone.utc)
    counts, unit, peak = runner._compute_histogram(ts, (window_dt, window_dt))
    assert counts == [3]
    assert peak == 3
    assert unit == "hr"


def test_histogram_right_edge_event_lands_in_final_bin() -> None:
    """An event at exactly data_window[1] must land in the final bin.

    Regression for the half-open-window defect: when the span is an exact
    multiple of bin_seconds (e.g. 24 hours with hourly bins), the prior
    implementation filtered out offsets equal to bin_count, silently
    undercounting the most-recent bin. data_window is derived from
    min(ts)/max(ts), so the max-ts event sits on the right edge by
    construction - it must land in the final bin, not be dropped.
    """
    start = datetime(2026, 6, 11, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(hours=24)  # exact 24h → bin_count == 24
    ts = pd.Series([start.timestamp(), end.timestamp()])
    counts, unit, peak = runner._compute_histogram(ts, (start, end))
    assert unit == "hr"               # locks the hourly binning branch
    assert len(counts) == 24
    assert counts[0] == 1
    assert counts[-1] == 1            # right-edge event lands in final bin
    assert peak == 1
    assert sum(counts) == 2           # no events lost


def test_histogram_caps_long_span_to_max_bins() -> None:
    """A 219-day span produces 219 raw daily bins; the width cap folds them
    so the single-line renderer can fit within terminal width."""
    start = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=219)
    ts = pd.Series([
        (start + timedelta(days=d, hours=12)).timestamp() for d in range(219)
    ])
    counts, unit, _peak = runner._compute_histogram(ts, (start, end))
    assert unit == "day"  # label stays nominal even when bins are folded
    assert len(counts) <= runner._HISTOGRAM_MAX_BINS
    # group_size = ceil(219 / 60) = 4 → ceil(219 / 4) = 55 folded buckets
    assert len(counts) == 55


def test_histogram_downsampling_preserves_total_event_count() -> None:
    """Folding adjacent bins by sum loses nothing - every raw event is
    accounted for in the post-fold counts."""
    start = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=219)
    ts = pd.Series([
        (start + timedelta(days=d, hours=12)).timestamp() for d in range(219)
    ])
    counts, _unit, _peak = runner._compute_histogram(ts, (start, end))
    assert sum(counts) == 219


def test_histogram_peak_reflects_post_fold_bucket() -> None:
    """Peak is recomputed AFTER the fold, so the rendered scale anchor
    reflects the summed bucket value the tallest glyph actually represents.

    Fixture: 219-day span (forces daily binning + cap to 55 buckets at
    group_size=4). Days 0-3 hold 3 events each; days 4-218 hold 1 event
    each. By construction the largest single-day raw count is 3, but the
    first folded bucket sums to 12 (3+3+3+3).
    """
    start = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=219)
    events: list[float] = []
    for d in range(4):
        for _ in range(3):
            events.append((start + timedelta(days=d, hours=12)).timestamp())
    for d in range(4, 219):
        events.append((start + timedelta(days=d, hours=12)).timestamp())
    ts = pd.Series(events)
    raw_max_single_bin = 3  # largest single-day raw count by construction
    counts, _unit, peak = runner._compute_histogram(ts, (start, end))
    assert peak == max(counts)
    assert peak > raw_max_single_bin
    assert peak == 12  # days 0-3 fold into bucket 0


def test_histogram_short_span_unchanged_by_cap() -> None:
    """Spans yielding <= 60 raw bins must be returned untouched - the cap
    must not perturb the common case. Locks concrete pre-cap values rather
    than mirroring the daily-switch test loosely.
    """
    start = datetime(2026, 5, 1, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=30)
    ts = pd.Series([
        (start + timedelta(days=d, hours=12)).timestamp() for d in range(30)
    ])
    counts, unit, peak = runner._compute_histogram(ts, (start, end))
    assert unit == "day"
    assert counts == [1] * 30  # exact pre-cap values, no folding
    assert peak == 1


def test_histogram_empty_frame_renders_no_events_line() -> None:
    rendered = _render_histogram([], "hr", 0)
    assert "no events in window" in rendered


def test_render_histogram_carries_axis_unit_label() -> None:
    hourly = _render_histogram([1, 2, 3], "hr", 3)
    assert "hourly bins" in hourly
    daily = _render_histogram([1, 2, 3], "day", 3)
    assert "daily bins" in daily


def test_render_histogram_carries_scale_anchor() -> None:
    rendered = _render_histogram([1, 5, 3], "hr", 5)
    assert "peak: 5" in rendered


def test_bar_glyph_low_and_high() -> None:
    assert _bar_glyph(0, 10) == "▁"
    assert _bar_glyph(10, 10) == "█"
    assert _bar_glyph(5, 10) in "▃▄▅"


def test_format_count_thresholds() -> None:
    assert _format_count(42) == "42"
    assert _format_count(1500) == "1.5k"
    assert _format_count(14_200) == "14.2k"
    assert _format_count(3_400_000) == "3.4M"


# ─── Ledes ───────────────────────────────────────────────────────────────────

def test_insights_silent_on_flat_pile() -> None:
    rows = [_conn_row(src=f"10.0.0.{i}", dst=f"192.0.2.{i}") for i in range(5)]
    df = _conn_df(rows)
    body = conn_digest.summarize(df)
    assert body["insights"] == []


def test_insights_sort_by_slot_ratio_not_cell_string() -> None:
    # Hand-build 4 speaking slots with distinct ratios; verify insights
    # verbalize the top 3 in ratio-desc order via the new selection helper.
    slots = [
        DigestSlot(label="conn-share", statistic="cliff", cells=["A", "10%", "2.0x"],
                   entity="A", magnitude=10.0, ratio=2.0),
        DigestSlot(label="densest-tuple", statistic="cliff", cells=["B → C:1", "5", "5.0x"],
                   entity="B → C:1", magnitude=5.0, ratio=5.0),
        DigestSlot(label="fan-out", statistic="cliff", cells=["D:2", "8 dsts", "4.0x"],
                   entity="D:2", magnitude=8.0, ratio=4.0),
        DigestSlot(label="byte-direction", statistic="cliff", cells=["E", "30%", "3.0x"],
                   entity="E", magnitude=30.0, ratio=3.0),
    ]
    insights, _ = _conn_insights_and_fields(slots)
    assert len(insights) == 3
    # Top three by ratio descending: densest-tuple (5.0), fan-out (4.0), byte-direction (3.0)
    assert "B → C:1" in insights[0]
    assert "D:2" in insights[1]
    # byte-direction lede MUST NOT lead with the vestigial " → " glyph -
    # the slot stores the bare dst now; only densest-tuple owns the
    # between-endpoints arrow.
    assert insights[2].startswith("E ")
    assert "→" not in insights[2]


def test_insights_verbalize_identity_and_magnitude() -> None:
    slot = DigestSlot(label="densest-tuple", statistic="cliff",
                      cells=["X → Y:22", "482", "3.7x"],
                      entity="X → Y:22", magnitude=482.0, ratio=3.7)
    insights, _ = _conn_insights_and_fields([slot])
    assert len(insights) == 1
    line = insights[0]
    assert "X → Y:22" in line
    assert "482" in line
    # Never reveal the raw statistic name
    assert "cliff" not in line.lower()
    assert "rank1" not in line.lower()


# ─── Display cap ─────────────────────────────────────────────────────────────

def test_format_ratio_cell_below_cap_renders_one_decimal() -> None:
    assert conn_digest._format_ratio_cell(3.7) == "3.7x"
    assert conn_digest._format_ratio_cell(49.9) == "49.9x"


def test_format_ratio_cell_at_or_above_cap_renders_capped_form() -> None:
    # Boundary is inclusive (>= cap)
    assert conn_digest._format_ratio_cell(50.0) == ">50x"
    assert conn_digest._format_ratio_cell(625000.0) == ">50x"


def test_format_ratio_lede_below_cap_renders_one_decimal() -> None:
    assert conn_digest._format_ratio_lede(3.7) == "3.7x"
    assert conn_digest._format_ratio_lede(49.9) == "49.9x"


def test_format_ratio_lede_at_or_above_cap_renders_prose_form() -> None:
    assert conn_digest._format_ratio_lede(50.0) == "more than 50x"
    assert conn_digest._format_ratio_lede(625000.0) == "more than 50x"


def test_ledes_sort_by_true_ratio_when_one_slot_is_capped() -> None:
    """The display cap must NOT corrupt lede sort order.

    A slot with a huge raw ratio (rendered capped) must still outrank a slot
    with a smaller raw ratio (rendered literally). Verifies the separation
    between stored slot.ratio (raw float, drives sort) and rendered display
    string (capped at CLIFF_DISPLAY_CAP).
    """
    capped = DigestSlot(
        label="byte-direction", statistic="cliff",
        cells=["A", "100%", ">50x"],
        entity="A", magnitude=100.0, ratio=625000.0,
    )
    uncapped = DigestSlot(
        label="densest-tuple", statistic="cliff",
        cells=["B → C:22", "9", "5.0x"],
        entity="B → C:22", magnitude=9.0, ratio=5.0,
    )
    # Intentionally pass uncapped first so the result reflects sort, not input order
    insights, _ = _conn_insights_and_fields([uncapped, capped])
    assert len(insights) == 2
    # Capped slot (raw 625000) sorts first by true ratio
    assert insights[0].startswith("A ")
    assert "more than 50x" in insights[0]
    assert "625000" not in insights[0]  # raw number must NOT leak into the rendered string
    # Uncapped slot sorts second, rendered as literal
    assert "B → C:22" in insights[1]
    assert "5.0x" in insights[1]


# ─── Summariser shape ────────────────────────────────────────────────────────

def test_summarizer_returns_zone1_insights_fields_keys() -> None:
    df = _conn_df([_conn_row()])
    body = conn_digest.summarize(df)
    assert set(body.keys()) == {"zone1_extras", "insights", "fields"}


def test_summarizer_zone1_extras_lead_with_hosts() -> None:
    df = _conn_df([_conn_row()])
    body = conn_digest.summarize(df)
    assert body["zone1_extras"][0][0] == "hosts"


# ─── Renderer (flat shape) ──────────────────────────────────────────────────

def _render_card(card: DigestCard) -> str:
    handler = TextHandler(stream=io.StringIO())
    handler.render_digest(card)
    return handler._stream.getvalue()


def _empty_card() -> DigestCard:
    return DigestCard(
        schema="conn",
        source_name="conn.log",
        data_window=(_NOW - timedelta(days=1), _NOW),
        record_count=0,
        histogram_counts=[],
        histogram_unit="hr",
        histogram_peak=0,
        zone1_extras=[("hosts", "0"), ("outbound bytes", "0 B"), ("inbound bytes", "0 B")],
        insights=[],
        fields=[],     # non-speaking slots are filtered before reaching the card
    )


def test_render_digest_identity_then_ambient() -> None:
    rendered = _render_card(_empty_card())
    lines = rendered.splitlines()
    # Identity line 1, then identity line 2 (window), then identity line 3
    # (schema · N lines · size), then blank, then ambient block.
    assert lines[0] == "conn.log"
    assert lines[2].startswith("conn · 0 lines ·")
    # Ambient block (label-aligned, flush-left).
    assert any(ln.startswith("hosts:") for ln in lines)
    # No banner, no schema rule, no N.B. footer.
    assert "Threat Hunt" not in rendered
    assert "── digest" not in rendered
    assert "N.B." not in rendered


def test_render_digest_non_speaking_slots_are_filtered_by_summariser() -> None:
    """A non-speaking slot never reaches `card.fields` - selection happens
    in the summariser. The renderer prints only what it gets and never
    paints a `label: -` row under the flat grammar."""
    rendered = _render_card(_empty_card())
    assert "conn-share:" not in rendered
    assert "fan-out:" not in rendered


def test_render_digest_field_block_shows_cells_for_speaking_non_insight_slot() -> None:
    slot = DigestSlot(
        label="densest-tuple", statistic="cliff",
        cells=["X → Y:22", "482", "3.7x"],
        entity="X → Y:22", magnitude=482.0, ratio=3.7,
    )
    card = DigestCard(
        schema="conn",
        source_name="conn.log",
        data_window=(_NOW - timedelta(days=1), _NOW),
        record_count=10,
        histogram_counts=[1, 2, 3],
        histogram_unit="hr",
        histogram_peak=3,
        zone1_extras=[("hosts", "1")],
        insights=[],
        fields=[slot],
        data_size_bytes=0,
    )
    rendered = _render_card(card)
    assert "densest-tuple: X → Y:22  482  3.7x" in rendered


# ─── Architectural fork: allowlist non-invocation ────────────────────────────

def test_run_digest_does_not_call_allowlist(tmp_path: Path, monkeypatch) -> None:
    """run_digest must never call build_matcher or AllowlistMatcher.filter_df.
    Patch both to raise; the digest run must complete cleanly."""
    zeek_dir = tmp_path / "zeek"
    rows = [
        _conn_row(src="10.0.0.10", dst="192.0.2.50",
                  ts=_BASE_TS - 3600 * (i + 1), local_orig=True)
        for i in range(6)
    ]
    _write_conn_ndjson(zeek_dir / "conn.log", rows)

    sentinel = RuntimeError("digest path violated pre-allowlist tap")

    from sigwood.common import allowlist as allowlist_mod
    def explode(*_args, **_kwargs):
        raise sentinel
    monkeypatch.setattr(allowlist_mod, "build_matcher", explode)
    monkeypatch.setattr(
        allowlist_mod.AllowlistMatcher, "filter_df",
        lambda self, df, name: (_ for _ in ()).throw(sentinel),
    )

    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    # Should complete with no allowlist interaction; capsys swallows the
    # rendered card so the test output stays clean.
    runner.run_digest(
        config=config, zeek_dir=zeek_dir, load_all=True, skip_confirm=True,
    )


# ─── Default-window paths ────────────────────────────────────────────────────

def test_run_digest_flat_layout_default_window_uses_data_max_ts(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Flat-layout default window must anchor to data max-ts, not now.

    Regression lock: an earlier plan draft proposed (now - span, now) as the
    flat-layout fallback. With archived logs whose max-ts is in the past,
    that approach silently discards everything. The corrected behaviour is
    [max_ts - span, max_ts] derived from the data itself.
    """
    zeek_dir = tmp_path / "zeek"
    # Far-past max-ts (5 years ago)
    far_past_max = _BASE_TS - 5 * 365 * 86400
    # Rows span 3 days before that max
    rows = []
    for i in range(6):
        rows.append(_conn_row(
            src=f"10.0.0.{i}", dst="192.0.2.20",
            ts=far_past_max - i * 86400,
        ))
    _write_conn_ndjson(zeek_dir / "conn.log", rows)

    config: dict[str, Any] = {"sigwood": {"default_window": "1d"}}
    runner.run_digest(config=config, zeek_dir=zeek_dir, skip_confirm=True)
    out = capsys.readouterr().out
    # The rendered identity-line-2 window covers only the last day of the
    # data - anchored to data-max-ts, not "now". The flat card has no
    # banner so there is no "Default window" note surface; window
    # correctness alone is the signal here.
    far_past_dt = datetime.fromtimestamp(far_past_max, tz=timezone.utc)
    assert far_past_dt.strftime("%Y-%m-%d") in out


def test_run_digest_dated_layout_default_window_uses_zeek_dated_helper(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Dated-layout default window must use zeek_dated_default_window."""
    zeek_dir = tmp_path / "zeek"
    # Two dated subdirs
    rows1 = [_conn_row(
        src=f"10.0.0.{i}", dst="192.0.2.10",
        ts=datetime(2026, 5, 30, 12, 0, tzinfo=timezone.utc).timestamp() + i,
    ) for i in range(3)]
    rows2 = [_conn_row(
        src=f"10.0.0.{i+10}", dst="192.0.2.20",
        ts=datetime(2026, 5, 31, 12, 0, tzinfo=timezone.utc).timestamp() + i,
    ) for i in range(3)]
    _write_conn_ndjson(zeek_dir / "2026-05-30" / "conn.log", rows1)
    _write_conn_ndjson(zeek_dir / "2026-05-31" / "conn.log", rows2)

    config: dict[str, Any] = {"sigwood": {"default_window": "1d"}}
    runner.run_digest(config=config, zeek_dir=zeek_dir, skip_confirm=True)
    out = capsys.readouterr().out
    # Only the most recent dated dir (2026-05-31) should be in the window
    assert "2026-05-31" in out


def test_run_digest_bounded_target_skips_default_window(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """A single conn.log file (bounded) must load in full - no default-window filter."""
    log_file = tmp_path / "conn.log"
    far_past_max = _BASE_TS - 5 * 365 * 86400
    rows = [_conn_row(
        src=f"10.0.0.{i}", dst="192.0.2.20",
        ts=far_past_max - i * 86400,
    ) for i in range(10)]
    _write_conn_ndjson(log_file, rows)

    config: dict[str, Any] = {"sigwood": {"default_window": "1d"}}
    runner.run_digest(config=config, zeek_dir=log_file, skip_confirm=True)
    out = capsys.readouterr().out
    # Bounded single-file targets load full → no default window resolved →
    # no disclosure note on the card.
    assert default_window_advisory("1d") not in out


# ─── Default-window disclosure note (BATCH 2) ───────────────────────────────
#
# A bare (unqualified) Zeek DIRECTORY digest resolves and APPLIES a default
# window; the card must DISCLOSE it (the live path was silently truncating).
# Gate = the resolver returned a window (run_digest's `if _digest_windows:`),
# so explicit since/until, --all, a single bounded file, and non-Zeek sources
# never disclose. The line reuses display.default_window_advisory so it can
# never drift from the analyze pre-load advisory.


def test_run_digest_flat_default_window_sets_and_renders_note(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Flat Zeek dir, unqualified, default_window=1d → the card carries
    default_window_note == display.default_window_advisory(spec) AND the
    rendered card prints that exact line."""
    zeek_dir = tmp_path / "zeek"
    rows = [
        _conn_row(src="192.0.2.10", dst="198.51.100.20", ts=_BASE_TS - i * 3600)
        for i in range(6)
    ]
    _write_conn_ndjson(zeek_dir / "conn.log", rows)

    captured: dict[str, Any] = {}
    orig = TextHandler.render_digest

    def _spy(self, card):
        captured["note"] = card.default_window_note
        return orig(self, card)

    monkeypatch.setattr(TextHandler, "render_digest", _spy)

    config: dict[str, Any] = {"sigwood": {"default_window": "1d"}}
    runner.run_digest(config=config, zeek_dir=zeek_dir, skip_confirm=True)
    out = capsys.readouterr().out

    assert captured["note"] == default_window_advisory("1d")
    assert default_window_advisory("1d") in out


def test_run_digest_dated_default_window_renders_note(
    tmp_path: Path, capsys
) -> None:
    """Dated Zeek layout, unqualified, default_window=1d → note present."""
    zeek_dir = tmp_path / "zeek"
    rows1 = [_conn_row(
        src="192.0.2.10", dst="198.51.100.20",
        ts=datetime(2026, 5, 30, 12, 0, tzinfo=timezone.utc).timestamp() + i,
    ) for i in range(3)]
    rows2 = [_conn_row(
        src="192.0.2.11", dst="198.51.100.21",
        ts=datetime(2026, 5, 31, 12, 0, tzinfo=timezone.utc).timestamp() + i,
    ) for i in range(3)]
    _write_conn_ndjson(zeek_dir / "2026-05-30" / "conn.log", rows1)
    _write_conn_ndjson(zeek_dir / "2026-05-31" / "conn.log", rows2)

    config: dict[str, Any] = {"sigwood": {"default_window": "1d"}}
    runner.run_digest(config=config, zeek_dir=zeek_dir, skip_confirm=True)
    out = capsys.readouterr().out
    assert default_window_advisory("1d") in out


def test_run_digest_explicit_since_suppresses_note(
    tmp_path: Path, capsys
) -> None:
    """An explicit --since means the resolver returns no default window →
    no disclosure note (the operator chose the window)."""
    zeek_dir = tmp_path / "zeek"
    rows = [
        _conn_row(src="192.0.2.10", dst="198.51.100.20", ts=_BASE_TS - i * 3600)
        for i in range(6)
    ]
    _write_conn_ndjson(zeek_dir / "conn.log", rows)

    config: dict[str, Any] = {"sigwood": {"default_window": "1d"}}
    runner.run_digest(
        config=config, zeek_dir=zeek_dir,
        since=datetime(2026, 6, 1, tzinfo=timezone.utc), skip_confirm=True,
    )
    out = capsys.readouterr().out
    assert default_window_advisory("1d") not in out


def test_run_digest_explicit_until_suppresses_note(
    tmp_path: Path, capsys
) -> None:
    """An explicit --until likewise suppresses the default-window note."""
    zeek_dir = tmp_path / "zeek"
    rows = [
        _conn_row(src="192.0.2.10", dst="198.51.100.20", ts=_BASE_TS - i * 3600)
        for i in range(6)
    ]
    _write_conn_ndjson(zeek_dir / "conn.log", rows)

    config: dict[str, Any] = {"sigwood": {"default_window": "1d"}}
    runner.run_digest(
        config=config, zeek_dir=zeek_dir,
        until=datetime(2026, 6, 30, tzinfo=timezone.utc), skip_confirm=True,
    )
    out = capsys.readouterr().out
    assert default_window_advisory("1d") not in out


def test_run_digest_load_all_suppresses_note(
    tmp_path: Path, capsys
) -> None:
    """--all means the full archive - the resolver returns no window → no note."""
    zeek_dir = tmp_path / "zeek"
    rows = [
        _conn_row(src="192.0.2.10", dst="198.51.100.20", ts=_BASE_TS - i * 3600)
        for i in range(6)
    ]
    _write_conn_ndjson(zeek_dir / "conn.log", rows)

    config: dict[str, Any] = {"sigwood": {"default_window": "1d"}}
    runner.run_digest(
        config=config, zeek_dir=zeek_dir, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    assert default_window_advisory("1d") not in out


# ─── -q / quiet: loader-bar combine ──────────────────────────────────────────

def _spy_load_logs_show_progress(monkeypatch, captured: dict) -> None:
    """Patch loader.load_logs to record show_progress and short-circuit.

    The single-file Zeek bypass calls loader.load_logs with run_digest's
    combined show_progress; a sentinel raise lets us observe it without
    fabricating downstream frames.
    """
    from sigwood.common import loader

    class _Stop(Exception):
        pass

    def _spy(*_a, show_progress=True, **_k):
        captured["show_progress"] = show_progress
        raise _Stop

    monkeypatch.setattr(loader, "load_logs", _spy)
    return _Stop


def test_run_digest_quiet_combines_to_no_loader_progress(tmp_path, monkeypatch):
    """quiet=True folds into the loader bar even when show_progress=True is
    passed (the fan-out's single-file default). Effective loader → False."""
    log_file = tmp_path / "conn.log"
    _write_conn_ndjson(log_file, [_conn_row(src="10.0.0.1", dst="192.0.2.20", ts=_BASE_TS)])
    captured: dict[str, Any] = {}
    stop = _spy_load_logs_show_progress(monkeypatch, captured)
    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    with pytest.raises(stop):
        runner.run_digest(
            config=config, zeek_dir=log_file, skip_confirm=True,
            show_progress=True, quiet=True,
        )
    assert captured["show_progress"] is False


def test_run_digest_not_quiet_keeps_loader_progress(tmp_path, monkeypatch):
    """Control: without quiet, show_progress=True reaches the loader unchanged."""
    log_file = tmp_path / "conn.log"
    _write_conn_ndjson(log_file, [_conn_row(src="10.0.0.1", dst="192.0.2.20", ts=_BASE_TS)])
    captured: dict[str, Any] = {}
    stop = _spy_load_logs_show_progress(monkeypatch, captured)
    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    with pytest.raises(stop):
        runner.run_digest(
            config=config, zeek_dir=log_file, skip_confirm=True,
            show_progress=True, quiet=False,
        )
    assert captured["show_progress"] is True


# ─── Single-file Zeek bypass: no basename gate on an explicit file ───────────

# run_digest MUST bypass discover_zeek_files for an explicit single Zeek file:
# discover_zeek_files' single-file branch gates on fnmatch(basename, pattern),
# which silently drops date-prefixed files (e.g. 2026-06-09.conn.log) into
# zero-row cards. Only the Zeek path needs this bypass (pihole/syslog/cloudtrail
# loaders accept explicit files without a basename gate); the detect path keeps
# the basename gate as a type check.

_TSV_CONN_HEADER = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
    "\tproto\tservice\tduration\torig_bytes\tresp_bytes"
    "\tconn_state\tlocal_orig\tlocal_resp\ttunnel_parents\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport"
    "\tenum\tstring\tinterval\tcount\tcount"
    "\tstring\tbool\tbool\tset[string]\n"
)


def test_run_digest_date_prefixed_zeek_ndjson_renders_card_with_rows(
    tmp_path: Path, capsys
) -> None:
    """Date-prefixed Zeek NDJSON single file renders a conn card with the
    real row count.

    The basename gate in discover_zeek_files must not drop this file as
    not matching ``conn*.log*``, leaving run_digest with an empty frame
    that renders as ``(no events in window)``.
    """
    log_file = tmp_path / "2026-06-09.conn.log"
    rows = [
        _conn_row(src=f"10.0.0.{i}", dst="192.0.2.20", ts=_BASE_TS - i)
        for i in range(6)
    ]
    _write_conn_ndjson(log_file, rows)

    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    runner.run_digest(
        config=config, zeek_dir=log_file, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    # Histogram has a real peak - not the empty-frame fallback.
    assert "(no events in window)" not in out
    assert "peak:" in out


def test_run_digest_date_prefixed_zeek_tsv_renders_card_with_rows(
    tmp_path: Path, capsys
) -> None:
    """Date-prefixed Zeek TSV single file with a complete header AND at
    least one data row renders a conn card.

    Proves the bypass reaches the Zeek strategy's prefix-preserving sniff
    (which dispatches TSV vs NDJSON across ``run_load``) and applies the
    conn normalizer - not just that sniff routed the file to the right
    schema.
    """
    log_file = tmp_path / "2026-06-09.conn.log"
    # Two data rows with distinct ts so the timeline has a non-zero span -
    # required by the ts-confidence guard in run_digest. The bypass under
    # test cares about file discovery + TSV parser routing, not span.
    log_file.write_text(
        _TSV_CONN_HEADER
        + "1748649600.000000\tCTest01\t192.0.2.10\t51514\t203.0.113.20\t443"
          "\ttcp\tssl\t3.5\t1500\t8200\tSF\tT\tF\t(empty)\n"
        + "1748649660.000000\tCTest02\t192.0.2.11\t51515\t203.0.113.20\t443"
          "\ttcp\tssl\t2.1\t800\t4400\tSF\tT\tF\t(empty)\n"
        + "#close\t2026-01-01-00:00:00\n",
        encoding="utf-8",
    )

    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    runner.run_digest(
        config=config, zeek_dir=log_file, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    assert "(no events in window)" not in out
    assert "peak:" in out


def test_run_digest_zeek_tsv_header_only_raises_digest_empty(
    tmp_path: Path
) -> None:
    """A Zeek TSV file with a complete ``#path conn`` header but zero data
    rows is RECOGNIZED-BUT-EMPTY: the header carries the schema, sniff
    routes it as conn, the loader returns an empty frame, and run_digest
    raises DigestEmpty (a control signal, not an error).

    Gate 2 seam: a zero-row schema card was misleading - it read as "we
    hunted and found nothing" rather than the truth ("we recognized it,
    there was nothing to read"). The CLI catches DigestEmpty in both
    entry paths and narrates "recognized X as conn but no parseable
    records - skipping"; this test pins the runner-level raise.
    """
    from sigwood.common.errors import DigestEmpty

    log_file = tmp_path / "2026-06-09.conn.log"
    log_file.write_text(
        _TSV_CONN_HEADER + "#close\t2026-01-01-00:00:00\n",
        encoding="utf-8",
    )

    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    with pytest.raises(DigestEmpty) as exc_info:
        runner.run_digest(
            config=config, zeek_dir=log_file, load_all=True, skip_confirm=True,
        )
    assert exc_info.value.schema == "conn"
    assert exc_info.value.basename == log_file.name


def test_run_digest_plain_conn_log_still_renders_card_with_rows(
    tmp_path: Path, capsys
) -> None:
    """Regression: a single file literally named ``conn.log`` (matches the
    old basename pattern) still loads and renders correctly. Confirms the
    bypass didn't break the previously-working filename case."""
    log_file = tmp_path / "conn.log"
    rows = [
        _conn_row(src=f"10.0.0.{i}", dst="192.0.2.20", ts=_BASE_TS - i)
        for i in range(6)
    ]
    _write_conn_ndjson(log_file, rows)

    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    runner.run_digest(
        config=config, zeek_dir=log_file, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    assert "(no events in window)" not in out
    assert "peak:" in out


# ─── Identity line 1: every card carries its source name ────────────────────


def test_run_digest_single_file_identity_line_is_basename(
    tmp_path: Path, capsys,
) -> None:
    """End-to-end: a single-file digest renders identity line 1 as the
    file's basename. No banner. The exact record count appears on
    identity line 3 (no glob-pattern key)."""
    log_file = tmp_path / "2026-05-30.conn.log"
    rows = [
        _conn_row(src=f"10.0.0.{i}", dst="192.0.2.20", ts=_BASE_TS - i)
        for i in range(6)
    ]
    _write_conn_ndjson(log_file, rows)

    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    runner.run_digest(
        config=config, zeek_dir=log_file, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0] == "2026-05-30.conn.log"
    # Identity line 3 - exact count, no glob-pattern key.
    schema_line = next(ln for ln in lines if ln.startswith("conn · "))
    assert "6 lines" in schema_line
    assert "conn*.log*" not in schema_line
    # No Source: banner row under the flat grammar.
    assert not any(ln.startswith("Source:") for ln in lines)


def test_run_digest_directory_mode_identity_line_is_dir_name(
    tmp_path: Path, capsys,
) -> None:
    """Directory-mode digest gets identity line 1 = directory's basename.
    source_name is not the file-vs-directory discriminator - every card has
    an identity line."""
    zeek_dir = tmp_path / "zeek"
    rows = [
        _conn_row(src=f"10.0.0.{i}", dst="192.0.2.20", ts=_BASE_TS - i)
        for i in range(6)
    ]
    _write_conn_ndjson(zeek_dir / "conn.log", rows)

    config: dict[str, Any] = {"sigwood": {"default_window": "all"}}
    runner.run_digest(
        config=config, zeek_dir=zeek_dir, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0] == "zeek"
    # No banner / Source: / Records: rows in the flat grammar.
    assert not any(ln.startswith("Source:") for ln in lines)
    assert not any(ln.startswith("Records:") for ln in lines)


# ─── CLI dispatch and whitelist enforcement ──────────────────────────────────

_ZEEK_NDJSON_CONN_LINE = (
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",'
    ' "id.resp_p": 443, "proto": "tcp", "duration": 1.23}\n'
)


def _write_zeek_conn_file(tmp_path: Path) -> Path:
    log_path = tmp_path / "conn.log"
    log_path.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    return log_path


def test_cli_digest_dispatch_routes_to_run_digest(tmp_path: Path, monkeypatch) -> None:
    import sigwood.cli as cli
    import sigwood.runner as runner_mod

    called: dict[str, Any] = {}
    def fake_run_digest(**kwargs):
        called.update(kwargs)
    monkeypatch.setattr(runner_mod, "run_digest", fake_run_digest)
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})

    log_path = _write_zeek_conn_file(tmp_path)
    cli._main(["digest", str(log_path), "--all"])
    assert called.get("schema") == "conn"
    # CLI passes raw strings; resolver owns Path conversion.
    assert called.get("zeek_dir") == str(log_path)
    assert called.get("load_all") is True


def test_cli_digest_rejects_detect_flag(monkeypatch) -> None:
    import sigwood.cli as cli
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})
    with pytest.raises(ValueError, match="--detect"):
        cli._main(["digest", "--detect=beacon"])


def test_cli_digest_rejects_non_text_output(tmp_path: Path, monkeypatch) -> None:
    import sigwood.cli as cli
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})
    log_path = _write_zeek_conn_file(tmp_path)
    with pytest.raises(ValueError, match="text"):
        cli._main(["digest", str(log_path), "--format=json", "--all"])


def test_run_digest_runner_seam_rejects_non_text_format() -> None:
    """The runner's defensive guard (the programmatic seam BELOW the CLI
    pre-check) pins the --format spelling too - a future CLI/config path
    that reaches it must not regress to a --output voice."""
    import sigwood.runner as runner
    with pytest.raises(ValueError, match=r"only --format=text"):
        runner.run_digest({}, output_format="json")


def test_cli_digest_rejects_filter_flag() -> None:
    """Filter / field flags aren't anywhere in the spec → plain unknown-flag."""
    import sigwood.cli as cli
    with pytest.raises(ValueError, match="unknown flag --filter"):
        cli._main(["digest", "--filter=src=192.0.2.10"])


def test_cli_digest_rejects_arbitrary_unknown_long_flag() -> None:
    import sigwood.cli as cli
    with pytest.raises(ValueError, match="unknown flag --field"):
        cli._main(["digest", "--field=src"])


def test_cli_digest_rejects_unknown_short_flag() -> None:
    import sigwood.cli as cli
    with pytest.raises(ValueError, match=r"unknown flag -x"):
        cli._main(["digest", "-x"])


def test_cli_digest_accepts_y_short_flag(tmp_path: Path, monkeypatch) -> None:
    import sigwood.cli as cli
    import sigwood.runner as runner_mod

    called: dict[str, Any] = {}
    def fake_run_digest(**kwargs):
        called.update(kwargs)
    monkeypatch.setattr(runner_mod, "run_digest", fake_run_digest)
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})

    log_path = _write_zeek_conn_file(tmp_path)
    cli._main(["digest", str(log_path), "-y", "--all"])
    assert called.get("skip_confirm") is True


def test_cli_digest_missing_path_surfaces_actionable_error_and_exits_nonzero(
    monkeypatch, capsys,
) -> None:
    """Per-path errors surface inline on stderr; with no card rendered the
    digest exit code is 1 (three-way tally: 0 rendered, ≥1 errored)."""
    import sigwood.cli as cli
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})
    rc = cli._main(["digest", "/no/such/file/here.log"])
    captured = capsys.readouterr()
    assert "not found" in captured.err
    assert rc == 1


def test_cli_digest_directory_positional_is_rejected_and_exits_nonzero(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """v1 sniff insists on filenames; directories do not fan out. The
    directory is surfaced inline on stderr and the run exits 1."""
    import sigwood.cli as cli
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})
    a_dir = tmp_path / "logs"
    a_dir.mkdir()
    rc = cli._main(["digest", str(a_dir)])
    captured = capsys.readouterr()
    assert "is a directory - digest takes a file" in captured.err
    assert rc == 1


def test_cli_digest_empty_file_prints_message_and_skips(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    import sigwood.cli as cli
    import sigwood.runner as runner_mod
    called: dict[str, Any] = {}
    def fake_run_digest(**kwargs):
        called.update(kwargs)
    monkeypatch.setattr(runner_mod, "run_digest", fake_run_digest)
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})

    empty = tmp_path / "nothing.log"
    empty.write_text("", encoding="utf-8")
    cli._main(["digest", str(empty)])
    captured = capsys.readouterr()
    assert "nothing.log is empty - nothing to do" in captured.out
    assert called == {}, "run_digest must NOT be invoked for an empty file"


def test_cli_digest_whitespace_only_file_prints_message_and_skips(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    import sigwood.cli as cli
    import sigwood.runner as runner_mod
    called: dict[str, Any] = {}
    def fake_run_digest(**kwargs):
        called.update(kwargs)
    monkeypatch.setattr(runner_mod, "run_digest", fake_run_digest)
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})

    blanks = tmp_path / "blanks.log"
    blanks.write_text("\n  \n\t\n", encoding="utf-8")
    cli._main(["digest", str(blanks)])
    captured = capsys.readouterr()
    assert "blanks.log is empty - nothing to do" in captured.out
    assert called == {}


def test_cli_digest_unrecognized_text_routes_to_blob(
    tmp_path: Path, monkeypatch,
) -> None:
    import sigwood.cli as cli
    import sigwood.runner as runner_mod
    called: dict[str, Any] = {}
    def fake_run_digest(**kwargs):
        called.update(kwargs)
    monkeypatch.setattr(runner_mod, "run_digest", fake_run_digest)
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})

    mystery = tmp_path / "mystery.txt"
    mystery.write_text("hello world\nlorem ipsum\n", encoding="utf-8")
    cli._main(["digest", str(mystery)])
    assert called.get("schema") == "blob"
    assert called.get("blob_path") == mystery


def test_cli_digest_bare_no_positional_uses_config_zeek_dir(
    tmp_path: Path, monkeypatch,
) -> None:
    """No positional → CLI passes config through unchanged; the config-driven
    conn fallback fires inside ``resolve_digest_source`` in ``run_digest``.

    This test asserts the CLI seam shape (zeek_dir override is None - the
    config flows in via the config dict). The actual config-fallback
    resolution is tested at the resolver layer
    (tests/test_sources.py:test_digest_conn_override_wins-style coverage
    + tests/test_root_provenance.py:test_runner_run_digest_applies_root_to_config_source_dirs).
    """
    import sigwood.cli as cli
    import sigwood.runner as runner_mod
    called: dict[str, Any] = {}
    def fake_run_digest(**kwargs):
        called.update(kwargs)
    monkeypatch.setattr(runner_mod, "run_digest", fake_run_digest)
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {"zeek_dir": str(zeek)}})

    cli._main(["digest"])
    assert called.get("schema") == "conn"
    # CLI seam: no override (None); config flows in via the config dict.
    assert called.get("zeek_dir") is None
    assert called["config"]["sigwood"]["zeek_dir"] == str(zeek)
