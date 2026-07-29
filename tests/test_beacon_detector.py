"""Beacon detector tests - FFT scorer properties and the run()-level contract.

Deterministic throughout: every synthetic train uses ``numpy.random.default_rng``
with a fixed seed and a fixed epoch anchor (the scorer is pure epoch math - no
timezone interaction). Score literals are pinned from live measurement; float
pins use small deltas rather than strict equality because FFT results can wobble
in the last rounded digit across platforms, while integer fields pin exactly.

Properties covered:
- In-band cadences report their true period regardless of jitter realization;
  the composite score varies with bin phase (bin-multiple cadences put arrivals
  near bin boundaries, so truncation noise feeds the prominence term).
- A 60s cadence sits at the 30s-bin band edge: mid-bin phases score
  near-deterministically, boundary-aligned phases score anchor-sensitively.
- The rfft grid cannot report a period below 60s at 30s bins (the grid floor);
  sub-60s cadences alias to longer reported periods (see docs/KNOWN-ISSUES.md).
- Aperiodic and single-burst traffic stays below threshold; degenerate inputs
  return None; the returned dict's key set is a stable contract.
"""

from __future__ import annotations

import importlib.util
import random
import unittest
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

import sigwood.detectors.beacon as beacon_module
from sigwood.common.finding import DetectorContext, Severity
from sigwood.detectors.beacon import (
    DEFAULT_CONFIG,
    _DEFAULT_HOME_NET,
    _MIN_RELIABLE_SPAN_DAYS,
    _compute_beacon_score,
    _filter_conn,
    _ip_in_home_net,
    _is_non_unicast,
    analyzed_span_seconds,
    non_established_share,
    run,
)
from tests.test_voice_consistency import assert_report_voice

_T0 = 1_750_000_000.0
_BIN = DEFAULT_CONFIG["bin_seconds"]
_THRESHOLD = DEFAULT_CONFIG["threshold"]
_WINDOW = (
    datetime(2026, 6, 1, tzinfo=timezone.utc),
    datetime(2026, 6, 2, tzinfo=timezone.utc),
)

_DEMO_GENERATOR = Path(__file__).resolve().parent.parent / "demo" / "gen_corpus.py"
_BEACON_REQUIRED_COLUMNS = (
    "conn_state",
    "bytes",
    "src",
    "dst",
    "port",
    "proto",
    "ts",
)


def _train(
    period: float,
    n: int,
    jitter: float,
    seed: int,
    *,
    phase: float = 0.0,
    lead: bool = False,
) -> np.ndarray:
    """Build a sorted arrival array: _T0 + phase + i*period + U(-jitter, jitter).

    ``lead`` prepends a bare arrival at exactly _T0. The scorer anchors its bin
    grid on the first arrival, so a lead arrival plus a mid-bin ``phase`` parks
    the train's arrivals away from bin boundaries (truncation never flips a
    bin), making the score realization-independent.
    """
    rng = np.random.default_rng(seed)
    arrivals = _T0 + phase + np.arange(n) * period + rng.uniform(-jitter, jitter, n)
    if lead:
        arrivals = np.concatenate([[_T0], arrivals])
    return np.sort(arrivals)


def _score(arr: np.ndarray) -> dict | None:
    return _compute_beacon_score(arr, _BIN)


def _conn_rows(
    ts_values, src: str, dst: str, port: int, *, local_orig: object = True
) -> list[dict]:
    """Rows that pass the connection prefilter: SF, local origin, bytes set.

    ``local_orig`` is keyword-tunable so a null-origin variant can exercise the
    effective-local fallback; drop the column from the frame for the absent case.
    """
    return [
        {
            "src": src,
            "dst": dst,
            "port": port,
            "proto": "tcp",
            "ts": float(t),
            "bytes": 512,
            "conn_state": "SF",
            "local_orig": local_orig,
        }
        for t in ts_values
    ]


def _ctx(
    df: pd.DataFrame | None,
    cfg: dict | None = None,
    *,
    home_net: list[str] | None = None,
) -> DetectorContext:
    logs = {"conn*.log*": df} if df is not None else {}
    return DetectorContext(
        logs=logs,
        config=cfg or {},
        allowlist=None,
        data_window=_WINDOW,
        home_net=home_net or [],
    )


def _scalar_eligibility_reference(
    frame: pd.DataFrame,
    home_net: list[str],
) -> tuple[pd.DataFrame, dict[str, int | tuple[str, ...]]]:
    """E3's scalar gate pipeline, retained as the cycle-2 parity oracle."""
    rows_total = len(frame)
    filtered = frame[frame["conn_state"].isin(["SF", "S1"])].copy()
    rows_after_state = len(filtered)
    if filtered.empty:
        return filtered, {
            "missing_columns": (),
            "rows_total": rows_total,
            "rows_after_state": rows_after_state,
            "rows_before_bytes": 0,
            "rows_after_bytes": 0,
            "rows_before_keys": 0,
            "rows_after_keys": 0,
        }
    filtered = filtered[
        ~filtered["dst"].map(_is_non_unicast).astype(bool)
    ]
    filtered = filtered[
        ~filtered["src"].map(_is_non_unicast).astype(bool)
    ]
    src_internal = filtered["src"].map(
        lambda ip: _ip_in_home_net(ip, home_net)
    )
    if "local_orig" not in filtered.columns:
        effective_local = src_internal.astype(bool)
    else:
        local_orig = filtered["local_orig"]
        effective_local = local_orig.where(
            local_orig.notna(), src_internal
        ).astype(bool)
    filtered = filtered[effective_local]
    rows_before_bytes = len(filtered)
    filtered = filtered[filtered["bytes"].notna()]
    rows_after_bytes = len(filtered)
    rows_before_keys = rows_after_bytes
    filtered = filtered[
        filtered[["src", "dst", "port", "proto"]].notna().all(axis=1)
    ]
    return filtered, {
        "missing_columns": (),
        "rows_total": rows_total,
        "rows_after_state": rows_after_state,
        "rows_before_bytes": rows_before_bytes,
        "rows_after_bytes": rows_after_bytes,
        "rows_before_keys": rows_before_keys,
        "rows_after_keys": len(filtered),
    }


def _load_demo_generator():
    """Import the demo corpus generator as a module (its main() is __main__-guarded)."""
    spec = importlib.util.spec_from_file_location(
        "gen_corpus_beacon_reference", _DEMO_GENERATOR
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class BeaconScorerTests(unittest.TestCase):
    """_compute_beacon_score properties on synthetic arrival trains."""

    def test_in_band_180s_period_accuracy(self):
        # A cleanly in-band cadence reports its true period; the composite
        # score is bin-phase-sensitive (180 is a bin multiple, so arrivals sit
        # near bin boundaries and this realization lands below threshold).
        # The pin guards period accuracy plus the exact realization score.
        result = _score(_train(180.0, 480, 3.5, 1801))
        self.assertIsNotNone(result)
        self.assertLessEqual(abs(result["dominant_period"] - 180.0), 3.6)
        self.assertAlmostEqual(result["beacon_score"], 0.4311, delta=0.001)

    def test_demo_reference_calibration(self):
        # Pins the demo corpus's seeded 180-second beacon (480 connections over
        # 24 hours) at ~0.62 - a SINGLE-DAY, FAVORABLE realization (near the top
        # of that flow's own jitter distribution), not the representative number;
        # test_representative_seven_day_180s_reliably_clears carries the reliable
        # 7-day band. Retained to catch demo-timing drift: the timing comes from
        # the real generator at its default seed, so a change to the demo's beacon
        # timing shows up here and forces a conscious documentation update. The
        # score is anchor-offset-invariant (the grid anchors on the first arrival),
        # so the pin holds for any regeneration anchor.
        gc = _load_demo_generator()
        rows: list[dict] = []
        rng_for = lambda ch: random.Random(3759 ^ gc.FLOW[ch])  # noqa: E731
        gc._gen_conn(rows, rng_for, _T0)
        # Generator rows are Zeek-native (pre-loader), keyed by id.resp_h.
        primary = np.sort(
            np.array(
                [r["ts"] for r in rows if r["id.resp_h"] == gc.C2_PRIMARY],
                dtype=float,
            )
        )
        result = _score(primary)
        self.assertIsNotNone(result)
        self.assertEqual(result["conn_count"], 480)
        self.assertGreaterEqual(result["beacon_score"], _THRESHOLD)
        self.assertAlmostEqual(result["beacon_score"], 0.6243, delta=0.001)
        self.assertLessEqual(abs(result["dominant_period"] - 180.0), 0.1)

    def test_in_band_600s_scores_over_threshold(self):
        result = _score(_train(600.0, 144, 6.0, 6001))
        self.assertIsNotNone(result)
        self.assertLessEqual(abs(result["dominant_period"] - 600.0), 12.0)
        self.assertGreaterEqual(result["beacon_score"], _THRESHOLD)
        self.assertAlmostEqual(result["beacon_score"], 0.6052, delta=0.001)

    def test_zero_jitter_180s_rewards_perfect_cadence(self):
        result = _score(_T0 + np.arange(480) * 180.0)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["jitter_cv"], 0.0)
        assert result["beacon_score"] == pytest.approx(0.5246, abs=0.001)
        self.assertGreaterEqual(result["beacon_score"], _THRESHOLD)

    def test_representative_seven_day_180s_reliably_clears(self):
        # A jittered 180s beacon over ~7 days (3360 * 180 = 604800s = exactly 7 days)
        # reliably clears threshold in a tight band - the reliability the span buys.
        # Contrast the single-day 180s realization (test_in_band_180s_period_accuracy,
        # 0.4311, below threshold): more span makes detection RELIABLE, not
        # higher-scoring - the 7-day band settles around 0.59-0.61, a touch below the
        # favorable single-day demo reference (~0.62).
        result = _score(_train(180.0, 3360, 6.0, 1807))
        self.assertIsNotNone(result)
        self.assertLessEqual(abs(result["dominant_period"] - 180.0), 0.1)
        self.assertAlmostEqual(result["beacon_score"], 0.5979, delta=0.001)
        # Reliability floor: comfortably above the 0.5 threshold, not marginal.
        self.assertGreaterEqual(result["beacon_score"], 0.55)

    def test_band_edge_60s_midbin_phase_is_stable(self):
        # Mid-bin phase (+bin/2 relative to the first-arrival-anchored grid)
        # keeps every arrival away from bin boundaries, so jitter never flips
        # a bin: identical counts, near-identical scores across realizations.
        scores = []
        for seed in range(3):
            result = _score(_train(60.0, 1440, 0.05, seed, phase=15.0, lead=True))
            self.assertIsNotNone(result)
            self.assertGreaterEqual(result["dominant_period"], 58.0)
            self.assertLessEqual(result["dominant_period"], 62.0)
            self.assertGreaterEqual(result["beacon_score"], _THRESHOLD)
            self.assertAlmostEqual(result["beacon_score"], 0.5574, delta=0.001)
            scores.append(result["beacon_score"])
        self.assertLess(max(scores) - min(scores), 0.05)

    def test_band_edge_60s_boundary_phase_is_anchor_sensitive(self):
        # Boundary-aligned arrivals (a bin-multiple cadence with no phase
        # offset) sit on bin edges, so truncation randomizes each arrival
        # between adjacent bins: identical flows score far apart, and the
        # dominant peak can wander off 60s entirely (observed strays: 75.2s
        # and 64.1s). Every report stays at or above the 60s grid floor.
        results = []
        for seed in range(10):
            result = _score(_train(60.0, 1440, 0.05, seed))
            self.assertIsNotNone(result)
            self.assertGreaterEqual(result["dominant_period"], 60.0)
            results.append(result)
        periods = [r["dominant_period"] for r in results]
        scores = [r["beacon_score"] for r in results]
        in_band = sum(1 for p in periods if 58.0 <= p <= 62.0)
        self.assertGreaterEqual(in_band, 8)
        self.assertGreater(max(scores) - min(scores), 0.2)
        self.assertLess(min(scores), _THRESHOLD)
        self.assertGreaterEqual(max(scores), _THRESHOLD)
        self.assertAlmostEqual(min(scores), 0.2133, delta=0.002)
        self.assertAlmostEqual(max(scores), 0.5846, delta=0.002)

    def test_sub_60s_cadence_aliases_to_longer_period(self):
        # A 45s cadence is below the 60s Nyquist floor of 30s bins: the flow
        # is detected, but the reported period aliases to ~90s - disclosed in
        # docs/KNOWN-ISSUES.md. The report must never claim the true sub-60s cadence.
        result = _score(_train(45.0, 1920, 0.5, 451))
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result["dominant_period"], 85.0)
        self.assertLessEqual(result["dominant_period"], 95.0)
        self.assertFalse(40.0 <= result["dominant_period"] <= 50.0)

    def test_grid_floor_even_bin_count_reports_exactly_60(self):
        # The rfft grid's minimum representable period is 2x the bin size:
        # exactly 60.0 at 30s bins on even bin counts. A genuine 60s beacon
        # lands on that floor bin and must stay admitted. _MIN_PERIOD stays
        # below 60 because the [45, 60) span is inert margin in exact
        # arithmetic, while float-computed Nyquist periods sit one ulp under
        # 60.0 on some bin counts - a mask opened at exactly 60 can reject a
        # clean 60s beacon outright.
        for seed in range(3):
            result = _score(_train(60.0, 119, 0.05, seed, phase=45.0, lead=True))
            self.assertIsNotNone(result)
            self.assertEqual(result["dominant_period"], 60.0)
            self.assertAlmostEqual(result["beacon_score"], 0.7998, delta=0.001)

    def test_grid_floor_odd_bin_count_reports_just_above_60(self):
        # Odd bin counts have no exact-60 grid point; the peak lands on the
        # nearest representable period just above the floor, never below it.
        for seed in range(3):
            result = _score(_train(60.0, 29, 0.05, seed, phase=15.0, lead=True))
            self.assertIsNotNone(result)
            self.assertGreater(result["dominant_period"], 60.0)
            self.assertLess(result["dominant_period"], 62.0)
            self.assertAlmostEqual(result["beacon_score"], 0.3367, delta=0.001)

    def test_poisson_arrivals_score_below_threshold(self):
        rng = np.random.default_rng(777)
        arr = np.sort(_T0 + np.cumsum(rng.exponential(180.0, 480)))
        result = _score(arr)
        self.assertTrue(result is None or result["beacon_score"] < _THRESHOLD)

    def test_single_burst_scores_below_threshold(self):
        # A single dense burst is admitted (it produces a spectrum) but its
        # jitter and weak periodicity keep the composite well under threshold.
        rng = np.random.default_rng(888)
        arr = np.sort(_T0 + rng.uniform(0, 300, 100))
        result = _score(arr)
        self.assertIsNotNone(result)
        self.assertLess(result["beacon_score"], _THRESHOLD)

    def test_too_few_points_returns_none(self):
        self.assertIsNone(_score(_T0 + np.arange(9) * 60.0))

    def test_zero_count_variance_returns_none(self):
        # All arrivals inside a single 30s bin: one bin, zero count variance.
        self.assertIsNone(_score(_T0 + np.linspace(0, 29, 15)))

    def test_return_contract(self):
        # The returned dict's key set is a stable contract; a deliberate
        # scorer change updates these pins consciously.
        result = _score(_train(180.0, 480, 3.5, 1801))
        self.assertIsNotNone(result)
        self.assertEqual(
            set(result.keys()),
            {
                "beacon_score",
                "dominant_period",
                "dominant_period_m",
                "spectral_ratio",
                "prominence",
                "prominence_norm",
                "jitter_cv",
                "conn_count",
                "occupancy",
            },
        )
        self.assertEqual(result["conn_count"], 480)
        self.assertAlmostEqual(result["beacon_score"], 0.4311, delta=0.001)
        self.assertAlmostEqual(result["dominant_period"], 180.0, delta=0.1)
        self.assertAlmostEqual(result["dominant_period_m"], 3.0, delta=0.01)
        self.assertAlmostEqual(result["spectral_ratio"], 0.024, delta=0.001)
        self.assertAlmostEqual(result["prominence"], 56.19, delta=0.1)
        self.assertAlmostEqual(result["prominence_norm"], 0.5619, delta=0.001)
        self.assertAlmostEqual(result["jitter_cv"], 0.0161, delta=0.001)
        self.assertAlmostEqual(result["occupancy"], 0.167, delta=0.001)


class BeaconRunTests(unittest.TestCase):
    """run()-level contract: thresholding, finding shape, ordering, empties."""

    @staticmethod
    def _passing_score_data(conn_count: int) -> dict:
        """A complete scorer result for evidence-assembly boundary tests."""
        return {
            "beacon_score": 0.6,
            "dominant_period": 600.0,
            "dominant_period_m": 10.0,
            "spectral_ratio": 0.1,
            "prominence": 50.0,
            "prominence_norm": 0.5,
            "jitter_cv": 0.1,
            "conn_count": conn_count,
            "occupancy": 0.1,
        }

    def test_single_beaconing_flow_yields_one_finding(self):
        rows = _conn_rows(
            _train(600.0, 144, 6.0, 6001), "192.0.2.10", "198.51.100.20", 443
        )
        # A second flow below the connection floor is never scored.
        rows += _conn_rows(
            _T0 + np.arange(19) * 60.0, "192.0.2.12", "198.51.100.22", 443
        )
        findings = run(_ctx(pd.DataFrame(rows)))
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.title, "192.0.2.10 → 198.51.100.20:443/tcp")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertIn("beacon_score", finding.evidence)
        self.assertIn("dominant_period", finding.evidence)
        self.assertAlmostEqual(finding.evidence["beacon_score"], 0.6052, delta=0.001)
        self.assertAlmostEqual(
            finding.evidence["dominant_period"], 600.0, delta=12.0
        )
        self.assertEqual(
            finding.description,
            "Connections recur on a near-fixed 10.0m period - the regular cadence "
            "of an automated check-in.",
        )
        self.assertEqual(
            finding.next_steps,
            [
                "Identify the process on 192.0.2.10 making connections every 10.0m",
                "Pivot to dns.log - search for lookups resolving to 198.51.100.20",
                "Review the full connection history for 198.51.100.20 in conn.log",
                "Check 198.51.100.20 on VirusTotal, Shodan, and ASN lookup",
                "Review allowlist controls: sigwood allowlist",
            ],
        )
        assert_report_voice(findings)

    def test_finding_carries_event_bounds_span_and_constructed_cycle_count(self):
        period = 600.0
        arrivals = _train(period, 144, 6.0, 6001)

        finding = run(_ctx(pd.DataFrame(_conn_rows(
            arrivals, "192.0.2.10", "198.51.100.20", 443
        ))))[0]

        self.assertEqual(
            finding.evidence["first_seen"],
            datetime.fromtimestamp(float(arrivals[0]), timezone.utc).isoformat(),
        )
        self.assertEqual(
            finding.evidence["last_seen"],
            datetime.fromtimestamp(float(arrivals[-1]), timezone.utc).isoformat(),
        )
        expected_span = float(arrivals[-1] - arrivals[0])
        self.assertAlmostEqual(finding.evidence["span_seconds"], expected_span, delta=1e-6)
        self.assertEqual(
            finding.evidence["cycles"],
            round(expected_span / period, 1),
        )

    def test_partially_non_finite_timestamps_keep_real_finite_bounds(self):
        arrivals = _train(600.0, 144, 6.0, 6001)
        expected_first = float(arrivals[0])
        expected_last = float(arrivals[-1])
        arrivals[50] = np.nan

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                "sigwood.detectors.beacon._compute_beacon_score",
                lambda ts, _bin: self._passing_score_data(len(ts)),
            )
            finding = run(_ctx(pd.DataFrame(_conn_rows(
                arrivals, "192.0.2.10", "198.51.100.20", 443
            ))))[0]

        self.assertEqual(
            finding.evidence["first_seen"],
            datetime.fromtimestamp(expected_first, timezone.utc).isoformat(),
        )
        self.assertEqual(
            finding.evidence["last_seen"],
            datetime.fromtimestamp(expected_last, timezone.utc).isoformat(),
        )
        self.assertAlmostEqual(
            finding.evidence["span_seconds"],
            expected_last - expected_first,
            delta=1e-6,
        )

    def test_invalid_event_bounds_are_all_none_and_run_does_not_raise(self):
        cases = {
            "all-non-finite": np.resize(np.array([np.nan, np.inf, -np.inf]), 20),
            "unrepresentable": 253_402_300_800.0 + np.arange(20) * 600.0,
        }
        for label, arrivals in cases.items():
            with self.subTest(label=label), pytest.MonkeyPatch.context() as monkeypatch:
                monkeypatch.setattr(
                    "sigwood.detectors.beacon._compute_beacon_score",
                    lambda ts, _bin: self._passing_score_data(len(ts)),
                )
                finding = run(_ctx(pd.DataFrame(_conn_rows(
                    arrivals, "192.0.2.10", "198.51.100.20", 443
                ))))[0]

                self.assertIsNone(finding.evidence["first_seen"])
                self.assertIsNone(finding.evidence["last_seen"])
                self.assertIsNone(finding.evidence["span_seconds"])
                self.assertIsNone(finding.evidence["cycles"])

    def test_epoch_zero_is_a_valid_event_bound(self):
        arrivals = _train(600.0, 144, 6.0, 6001)
        arrivals -= arrivals[0]

        finding = run(_ctx(pd.DataFrame(_conn_rows(
            arrivals, "192.0.2.10", "198.51.100.20", 443
        ))))[0]

        self.assertEqual(
            finding.evidence["first_seen"],
            "1970-01-01T00:00:00+00:00",
        )

    def test_score_pass_caps_at_medium(self):
        rows = _conn_rows(
            _train(600.0, 144, 6.0, 6001), "192.0.2.10", "198.51.100.20", 443
        )
        for score in (0.5, 0.7):
            with self.subTest(score=score), pytest.MonkeyPatch.context() as monkeypatch:
                monkeypatch.setattr(
                    "sigwood.detectors.beacon._compute_beacon_score",
                    lambda _ts, _bin: {
                        "beacon_score": score,
                        "dominant_period": 600.0,
                        "dominant_period_m": 10.0,
                        "spectral_ratio": 0.1,
                        "prominence": 50.0,
                        "prominence_norm": 0.5,
                        "jitter_cv": 0.1,
                        "conn_count": 144,
                        "occupancy": 0.1,
                    },
                )
                finding = run(_ctx(pd.DataFrame(rows)))[0]
            self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_lowered_threshold_keeps_sub_half_score_low(self):
        rows = _conn_rows(
            _train(180.0, 480, 3.5, 1801), "192.0.2.10", "198.51.100.20", 443
        )
        findings = run(_ctx(pd.DataFrame(rows), {"threshold": 0.4}))
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0].evidence["beacon_score"], 0.4311, delta=0.001)
        self.assertEqual(findings[0].severity, Severity.LOW)

    def test_findings_sorted_by_score_descending(self):
        rows = _conn_rows(
            _train(600.0, 144, 6.0, 6001), "192.0.2.10", "198.51.100.20", 443
        )
        rows += _conn_rows(
            _train(60.0, 1440, 0.05, 0, phase=15.0, lead=True),
            "192.0.2.11",
            "198.51.100.21",
            8443,
        )
        findings = run(_ctx(pd.DataFrame(rows)))
        self.assertEqual(len(findings), 2)
        scores = [f.evidence["beacon_score"] for f in findings]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(findings[0].title, "192.0.2.10 → 198.51.100.20:443/tcp")
        self.assertEqual(findings[1].title, "192.0.2.11 → 198.51.100.21:8443/tcp")

    def test_missing_pattern_key_returns_empty(self):
        self.assertEqual(run(_ctx(None)), [])

    def test_empty_frame_returns_empty(self):
        self.assertEqual(run(_ctx(pd.DataFrame())), [])

    def test_each_missing_beacon_required_column_abstains_and_reports_exactly_it(self):
        """Every absent precondition is a clean abstention, including ts after the floor."""
        frame = pd.DataFrame(_conn_rows(
            _T0 + np.arange(20) * 600.0,
            "192.0.2.10",
            "198.51.100.20",
            443,
        ))
        for column in _BEACON_REQUIRED_COLUMNS:
            with self.subTest(column=column):
                missing = frame.drop(columns=[column])
                self.assertEqual(run(_ctx(missing)), [])
                facts = beacon_module.scoring_eligibility(
                    missing, ["192.0.2.0/24"]
                )
                self.assertEqual(facts["missing_columns"], (column,))
                filtered = beacon_module._filter_conn(
                    missing, ["192.0.2.0/24"]
                )
                self.assertTrue(filtered.empty)
                self.assertEqual(list(filtered.columns), list(missing.columns))

    def test_null_grouping_key_filter_preserves_healthy_scored_set(self):
        """The explicit key gate must match pandas' historical dropna=True population."""
        rows = _conn_rows(
            _T0 + np.arange(20) * 600.0,
            "192.0.2.10",
            "198.51.100.20",
            443,
        )
        rows += _conn_rows(
            _T0 + np.arange(20) * 600.0,
            "192.0.2.11",
            "198.51.100.21",
            8443,
        )
        null_key_rows = _conn_rows(
            _T0 + np.arange(4) * 600.0,
            "192.0.2.12",
            "198.51.100.22",
            9443,
        )
        for row in null_key_rows:
            row["port"] = None
        calls: list[tuple[str, str, int, str]] = []
        real_make = beacon_module._make_finding

        def _record_make(src, dst, port, proto, *args, **kwargs):
            calls.append((src, dst, port, proto))
            return real_make(src, dst, port, proto, *args, **kwargs)

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                beacon_module,
                "_compute_beacon_score",
                lambda ts, _bin: self._passing_score_data(len(ts)),
            )
            monkeypatch.setattr(beacon_module, "_make_finding", _record_make)
            findings = run(_ctx(pd.DataFrame(rows + null_key_rows)))

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            set(calls),
            {
                ("192.0.2.10", "198.51.100.20", 443, "tcp"),
                ("192.0.2.11", "198.51.100.21", 8443, "tcp"),
            },
        )


class BeaconEligibilityTests(unittest.TestCase):
    """Eligibility accounting follows the detector gates and is total/defensive."""

    def test_distinct_classification_fast_path_calls_once_per_unique(self):
        """Hashable duplicates are classified by value at all three IP sites."""
        row_count = 24
        frame = pd.DataFrame(_conn_rows(
            _T0 + np.arange(row_count) * 60.0,
            "192.0.2.10",
            "198.51.100.20",
            443,
        ))
        frame["src"] = (
            ["192.0.2.10"] * 12
            + ["192.0.2.11"] * 11
            + [None]
        )
        frame["dst"] = (
            ["198.51.100.20"] * 12
            + ["198.51.100.21"] * 11
            + [np.nan]
        )
        home_net = ["192.0.2.0/24"]
        expected_frame, expected_facts = _scalar_eligibility_reference(
            frame, home_net
        )

        real_non_unicast = beacon_module._is_non_unicast
        real_in_home_net = beacon_module._ip_in_home_net
        non_unicast_calls: list[object] = []
        home_net_calls: list[object] = []

        def _count_non_unicast(value: object) -> bool:
            non_unicast_calls.append(value)
            return real_non_unicast(value)

        def _count_in_home_net(value: object, networks: list[str]) -> bool:
            home_net_calls.append(value)
            return real_in_home_net(value, networks)

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                beacon_module, "_is_non_unicast", _count_non_unicast
            )
            monkeypatch.setattr(
                beacon_module, "_ip_in_home_net", _count_in_home_net
            )
            actual_frame, actual_facts = (
                beacon_module._apply_scoring_eligibility(frame, home_net)
            )

        post_state = frame[frame["conn_state"].isin(["SF", "S1"])]
        post_dst = post_state[
            ~post_state["dst"].map(real_non_unicast).astype(bool)
        ]
        dst_distinct = list(pd.unique(post_state["dst"].dropna()))
        src_distinct = list(pd.unique(post_dst["src"].dropna()))

        self.assertEqual(actual_frame.equals(expected_frame), True)
        self.assertEqual(actual_facts, expected_facts)
        self.assertEqual(actual_facts["rows_before_bytes"], row_count)
        self.assertEqual(actual_facts["rows_after_bytes"], row_count)
        self.assertEqual(actual_facts["rows_before_keys"], row_count)
        self.assertEqual(actual_facts["rows_after_keys"], row_count - 1)
        self.assertEqual(
            Counter(value for value in non_unicast_calls if value is not None),
            Counter(dst_distinct + src_distinct),
        )
        self.assertEqual(
            sum(value is None for value in non_unicast_calls), 2
        )
        self.assertEqual(
            Counter(value for value in home_net_calls if value is not None),
            Counter(src_distinct),
        )
        self.assertEqual(sum(value is None for value in home_net_calls), 1)
        self.assertLess(len(non_unicast_calls), row_count)
        self.assertLess(len(home_net_calls), row_count)

    def test_unhashable_classification_fallback_has_scalar_parity(self):
        """List/dict cells attempt factorization, then retain E3 tolerance."""
        frame = pd.DataFrame(_conn_rows(
            _T0 + np.arange(8) * 60.0,
            "192.0.2.10",
            "198.51.100.20",
            443,
        ))
        frame.at[0, "dst"] = ["198.51.100.20"]
        frame.at[1, "src"] = {"ip": "192.0.2.10"}
        frame.at[2, "dst"] = np.nan
        frame.at[3, "src"] = None
        frame.at[4, "dst"] = 3
        frame.at[5, "src"] = "fe80::1%eth0"
        frame.at[7, "dst"] = "224.0.0.1"
        home_net = ["192.0.2.0/24"]
        expected_frame, expected_facts = _scalar_eligibility_reference(
            frame, home_net
        )
        real_factorize = pd.factorize
        attempts = 0
        fallbacks = 0

        def _factorize_spy(*args, **kwargs):
            nonlocal attempts, fallbacks
            attempts += 1
            try:
                return real_factorize(*args, **kwargs)
            except (TypeError, ValueError):
                fallbacks += 1
                raise

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                beacon_module.pd, "factorize", _factorize_spy
            )
            actual_frame = beacon_module._filter_conn(frame, home_net)
            actual_facts = beacon_module.scoring_eligibility(frame, home_net)

        self.assertEqual(actual_frame.equals(expected_frame), True)
        self.assertEqual(actual_facts, expected_facts)
        self.assertEqual(attempts, 6)
        self.assertEqual(fallbacks, 6)

    def test_all_missing_and_empty_address_frames_preserve_facts(self):
        empty = pd.DataFrame(columns=[
            "src", "dst", "port", "proto", "ts", "bytes", "conn_state",
            "local_orig",
        ])
        empty_frame, empty_facts = beacon_module._apply_scoring_eligibility(
            empty, ["192.0.2.0/24"]
        )
        self.assertEqual(empty_frame.equals(empty), True)
        self.assertEqual(
            empty_facts,
            {
                "missing_columns": (),
                "rows_total": 0,
                "rows_after_state": 0,
                "rows_before_bytes": 0,
                "rows_after_bytes": 0,
                "rows_before_keys": 0,
                "rows_after_keys": 0,
            },
        )

        all_missing = pd.DataFrame(_conn_rows(
            _T0 + np.arange(4) * 60.0,
            "192.0.2.10",
            "198.51.100.20",
            443,
        ))
        all_missing["src"] = None
        all_missing["dst"] = np.nan
        expected_frame, expected_facts = _scalar_eligibility_reference(
            all_missing, ["192.0.2.0/24"]
        )
        actual_frame, actual_facts = (
            beacon_module._apply_scoring_eligibility(
                all_missing, ["192.0.2.0/24"]
            )
        )
        self.assertEqual(actual_frame.equals(expected_frame), True)
        self.assertEqual(actual_facts, expected_facts)

    def test_counts_follow_state_address_local_bytes_and_key_gates(self):
        frame = pd.DataFrame(_conn_rows(
            _T0 + np.arange(6) * 60.0,
            "192.0.2.10",
            "198.51.100.20",
            443,
        ))
        frame.loc[0, "conn_state"] = "S0"
        frame.loc[1, "dst"] = "224.0.0.1"
        frame.loc[2, "local_orig"] = False
        frame.loc[3, "bytes"] = None
        frame.loc[4, "port"] = None

        self.assertEqual(
            beacon_module.scoring_eligibility(frame, ["192.0.2.0/24"]),
            {
                "missing_columns": (),
                "rows_total": 6,
                "rows_after_state": 5,
                "rows_before_bytes": 3,
                "rows_after_bytes": 2,
                "rows_before_keys": 2,
                "rows_after_keys": 1,
            },
        )

    def test_custom_home_net_drives_the_effective_local_count(self):
        frame = pd.DataFrame(_conn_rows(
            [_T0],
            "203.0.113.10",
            "198.51.100.20",
            443,
            local_orig=None,
        ))
        custom = beacon_module.scoring_eligibility(frame, ["203.0.113.0/24"])
        fallback = beacon_module.scoring_eligibility(frame)
        self.assertEqual(custom["rows_before_bytes"], 1)
        self.assertEqual(fallback["rows_before_bytes"], 0)

    def test_unexpected_shape_returns_complete_no_measurement_dictionary(self):
        self.assertEqual(
            beacon_module.scoring_eligibility(object()),
            {
                "missing_columns": _BEACON_REQUIRED_COLUMNS,
                "rows_total": 0,
                "rows_after_state": 0,
                "rows_before_bytes": 0,
                "rows_after_bytes": 0,
                "rows_before_keys": 0,
                "rows_after_keys": 0,
            },
        )

    def test_partial_and_total_null_grouping_key_counts(self):
        for key in ("src", "dst", "port", "proto"):
            with self.subTest(key=key):
                frame = pd.DataFrame(_conn_rows(
                    _T0 + np.arange(4) * 60.0,
                    "192.0.2.10",
                    "198.51.100.20",
                    443,
                ))
                frame.loc[0, key] = None
                partial = beacon_module.scoring_eligibility(frame)
                self.assertEqual(partial["rows_before_keys"], 4)
                self.assertEqual(partial["rows_after_keys"], 3)

        frame = pd.DataFrame(_conn_rows(
            _T0 + np.arange(4) * 60.0,
            "192.0.2.10",
            "198.51.100.20",
            443,
        ))
        frame["port"] = None
        total = beacon_module.scoring_eligibility(frame)
        self.assertEqual(total["rows_before_keys"], 4)
        self.assertEqual(total["rows_after_keys"], 0)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"threshold": 0}, r"\[detectors\.beacon\]\.threshold"),
        ({"threshold": 1.01}, r"\[detectors\.beacon\]\.threshold"),
        ({"threshold": np.nan}, r"\[detectors\.beacon\]\.threshold"),
        ({"threshold": np.inf}, r"\[detectors\.beacon\]\.threshold"),
        ({"threshold": -np.inf}, r"\[detectors\.beacon\]\.threshold"),
        ({"threshold": "0.5"}, r"\[detectors\.beacon\]\.threshold"),
        ({"threshold": True}, r"\[detectors\.beacon\]\.threshold"),
        ({"min_connections": 0}, r"\[detectors\.beacon\]\.min_connections"),
        ({"min_connections": 1.5}, r"\[detectors\.beacon\]\.min_connections"),
        ({"min_connections": True}, r"\[detectors\.beacon\]\.min_connections"),
        ({"bin_seconds": 0}, r"\[detectors\.beacon\]\.bin_seconds"),
        ({"bin_seconds": -1}, r"\[detectors\.beacon\]\.bin_seconds"),
        ({"bin_seconds": 1.5}, r"\[detectors\.beacon\]\.bin_seconds"),
        ({"bin_seconds": True}, r"\[detectors\.beacon\]\.bin_seconds"),
    ],
)
def test_validate_config_rejects_invalid_values(
    overrides: dict, message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        beacon_module.validate_config({**DEFAULT_CONFIG, **overrides})


@pytest.mark.parametrize("min_connections", [9, 10])
def test_validate_config_accepts_floor_advisory_values(min_connections: int) -> None:
    beacon_module.validate_config({
        **DEFAULT_CONFIG,
        "min_connections": min_connections,
        "future_key": "ignored",
    })


def test_validate_config_accepts_threshold_upper_bound() -> None:
    beacon_module.validate_config({**DEFAULT_CONFIG, "threshold": 1.0})


class BeaconPrefilterTests(unittest.TestCase):
    """Pre-filter contract: empty-survivor no-crash, effective-local fallback, disclosure."""

    def test_no_established_survivors_does_not_crash(self):
        # Zero {SF,S1} survivors once emptied the frame, and a .map-derived object
        # mask on the empty frame was read by pandas as column selection (frame
        # collapses to zero columns, then df["src"] KeyErrors). run() returns [].
        for state in ("S0", "REJ"):
            with self.subTest(state=state):
                df = pd.DataFrame(
                    _conn_rows(_T0 + np.arange(30) * 60.0, "192.0.2.10", "198.51.100.20", 443)
                )
                df["conn_state"] = state
                self.assertEqual(run(_ctx(df)), [])

    def test_null_local_orig_falls_back_to_home_net_membership(self):
        # local_orig all-null (a sensor without Site::local_nets): the source's
        # home_net membership decides. src in home_net -> the flow is scored and emits.
        rows = _conn_rows(
            _train(600.0, 144, 6.0, 6001), "192.0.2.10", "198.51.100.20", 443,
            local_orig=None,
        )
        findings = run(_ctx(pd.DataFrame(rows), home_net=["192.0.2.0/24"]))
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0].evidence["beacon_score"], 0.6052, delta=0.001)
        # src outside home_net (and no sensor signal) -> excluded, nothing emitted.
        findings = run(_ctx(pd.DataFrame(rows), home_net=["198.51.100.0/24"]))
        self.assertEqual(findings, [])

    def test_absent_local_orig_column_falls_back_to_home_net_membership(self):
        rows = _conn_rows(
            _train(600.0, 144, 6.0, 6001), "192.0.2.10", "198.51.100.20", 443,
            local_orig=None,
        )
        df = pd.DataFrame(rows).drop(columns=["local_orig"])
        findings = run(_ctx(df, home_net=["192.0.2.0/24"]))
        self.assertEqual(len(findings), 1)

    def test_set_local_orig_wins_over_membership(self):
        # local_orig=False excluded even when src is in home_net; local_orig=True kept
        # even when src is outside home_net - the sensor wins when it speaks.
        rows = _conn_rows(
            _T0 + np.arange(5), "192.0.2.10", "198.51.100.20", 443, local_orig=False
        )
        rows += _conn_rows(
            _T0 + np.arange(5), "198.51.100.50", "198.51.100.20", 443, local_orig=True
        )
        out = _filter_conn(pd.DataFrame(rows), ["192.0.2.0/24"])
        self.assertEqual(sorted(out["src"].unique().tolist()), ["198.51.100.50"])

    def test_filter_empties_at_link_local_preserves_columns(self):
        # The only {SF,S1} survivor is an fe80 link-local row, dropped by the
        # non-unicast filter AFTER the conn_state gate but BEFORE the local mask.
        # No raise, and the returned empty frame keeps its columns.
        df = pd.DataFrame(_conn_rows(_T0 + np.arange(3), "fe80::1", "198.51.100.20", 443))
        out = _filter_conn(df, _DEFAULT_HOME_NET)
        self.assertTrue(out.empty)
        self.assertEqual(list(out.columns), list(df.columns))

    def test_ip_in_home_net_guard_shape(self):
        self.assertTrue(_ip_in_home_net("192.0.2.10", ["192.0.2.0/24"]))
        self.assertFalse(_ip_in_home_net("192.0.2.10", ["198.51.100.0/24"]))
        for bad in (None, np.nan, "", "not-an-ip", 42):
            self.assertFalse(_ip_in_home_net(bad, ["192.0.2.0/24"]))

    def test_is_non_unicast_classifier(self):
        # A unicast ".255" host in a network wider than /24 is kept (not treated as
        # broadcast); multicast, link-local, and the limited broadcast are excluded;
        # junk never raises.
        for keep in ("192.0.2.255", "10.0.0.255", "203.0.113.1", "2001:db8::1"):
            self.assertFalse(_is_non_unicast(keep), keep)
        for excl in ("224.0.0.1", "239.1.2.3", "232.1.2.3", "255.255.255.255",
                     "169.254.1.5", "fe80::1", "ff02::1", "ff35::1"):
            self.assertTrue(_is_non_unicast(excl), excl)
        for bad in (None, "not-an-ip", "", 42):
            self.assertFalse(_is_non_unicast(bad), bad)

    def test_filter_gates_non_unicast_both_columns_keeps_unicast_dot255(self):
        # Both columns gate non-unicast: a real internal->external beacon to a unicast
        # ".255" host in a network wider than /24 survives the pre-filter and reaches
        # scoring, while multicast and link-local destinations are excluded.
        hn = ["192.0.2.0/23"]
        keep = pd.DataFrame(_conn_rows(_T0 + np.arange(3), "192.0.2.10", "192.0.2.255", 443))
        self.assertEqual(len(_filter_conn(keep, hn)), 3)
        for bad_dst in ("224.0.0.1", "169.254.1.5"):
            df = pd.DataFrame(_conn_rows(_T0 + np.arange(3), "192.0.2.10", bad_dst, 443))
            self.assertTrue(_filter_conn(df, hn).empty, bad_dst)
        # Source-side non-unicast rows are excluded even when local_orig marks them local
        # (local_orig=True pushes them past the effective-local gate, so the source
        # non-unicast filter is the only thing that can drop them); a unicast ".255" source
        # remains admissible.
        for bad_src in ("169.254.1.5", "ff02::1"):
            df = pd.DataFrame(
                _conn_rows(_T0 + np.arange(3), bad_src, "198.51.100.20", 443, local_orig=True)
            )
            self.assertTrue(_filter_conn(df, _DEFAULT_HOME_NET).empty, bad_src)
        df = pd.DataFrame(
            _conn_rows(_T0 + np.arange(3), "192.0.2.255", "198.51.100.20", 443, local_orig=True)
        )
        self.assertEqual(len(_filter_conn(df, _DEFAULT_HOME_NET)), 3)

    def test_non_established_share_defensive_on_missing_conn_state(self):
        df = pd.DataFrame(_conn_rows(_T0 + np.arange(4), "192.0.2.10", "198.51.100.20", 443))
        df.loc[0, "conn_state"] = "S0"
        self.assertEqual(non_established_share(df), (1, 4))
        self.assertEqual(non_established_share(df.drop(columns=["conn_state"])), (0, 4))


class BeaconSpanHelperTests(unittest.TestCase):
    """analyzed_span_seconds: a real span on good input, the 0.0 no-measurement
    sentinel on every degenerate shape, and never a raise (it runs outside the
    detector's error containment)."""

    def test_min_reliable_span_days_is_a_week(self):
        # The runner's span-note floor sources this single constant.
        self.assertEqual(_MIN_RELIABLE_SPAN_DAYS, 7)

    def test_multi_day_frame_returns_span(self):
        df = pd.DataFrame({"ts": [_T0, _T0 + 3 * 86400.0, _T0 + 86400.0]})
        self.assertAlmostEqual(analyzed_span_seconds(df), 3 * 86400.0, delta=1e-6)

    def test_empty_frame_returns_zero(self):
        self.assertEqual(analyzed_span_seconds(pd.DataFrame()), 0.0)

    def test_ts_absent_frame_returns_zero(self):
        self.assertEqual(analyzed_span_seconds(pd.DataFrame({"src": ["a", "b"]})), 0.0)

    def test_single_row_frame_returns_zero(self):
        self.assertEqual(analyzed_span_seconds(pd.DataFrame({"ts": [_T0]})), 0.0)

    def test_all_nan_ts_returns_zero(self):
        self.assertEqual(analyzed_span_seconds(pd.DataFrame({"ts": [np.nan, np.nan]})), 0.0)

    def test_non_numeric_ts_returns_zero_without_raising(self):
        self.assertEqual(analyzed_span_seconds(pd.DataFrame({"ts": ["x", "y"]})), 0.0)


if __name__ == "__main__":
    unittest.main()
