"""Tests for the syslog anomaly detector.

All IP addresses and hostnames use RFC 5737 documentation space:
  192.0.2.x, 198.51.100.x, 203.0.113.x
No real network data appears anywhere in this file.

Strategy: run() tests monkeypatch _run_drain3 to inject pre-labelled template
columns, so test outcomes are independent of drain3 clustering behaviour.
The drain3 function itself has its own smoke test.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
import warnings
from collections import Counter, namedtuple
from datetime import datetime, timezone

from tests.test_voice_consistency import assert_report_voice
from unittest.mock import patch

import pandas as pd

from sigwood.common.finding import DetectorContext, Finding, Severity
from sigwood.detectors.syslog import (
    DETECTOR_NAME,
    STATUS,
    REBOOT_CLUSTER_SECONDS,
    _BootEvent,
    _collapse_bursts,
    _collapse_families,
    _detect_boot_events,
    _gap_cluster,
    _reboot_finding,
    _reconcile,
    _run_drain3,
    run,
)
from sigwood.parsers.syslog import REBOOT_SIGNALS_RE, is_reboot_signal
from sigwood.parsers.journal import parse_record as parse_journal_record
from sigwood.outputs._render_model import Section as _Section


def _flat_section(findings: list[Finding]) -> list[_Section]:
    """Wrap findings into the single-section shape per the renderer contract."""
    return [_Section(None, list(findings), len(findings))]

_NOW    = datetime(2026, 5, 30, tzinfo=timezone.utc)
_WINDOW = (_NOW, _NOW)

# Fixed unix epoch used across fixtures (2026-05-30 00:00:00 UTC)
_BASE_TS = 1_748_563_200.0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_df(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=["ts", "host", "raw", "message"])


def _ctx(df: pd.DataFrame, cfg: dict | None = None) -> DetectorContext:
    return DetectorContext(
        logs={"*.log*": df},
        config=cfg or {},
        allowlist=None,
        data_window=_WINDOW,
    )


def _common_row(i: int, ts_offset: float = 0.0) -> dict:
    """A row whose message belongs to the high-frequency common template."""
    return {
        "ts":      _BASE_TS + ts_offset + i * 60.0,
        "host":    "192.0.2.1",
        "raw":     f"<30>May 30 12:{i:02d}:00 192.0.2.1 sshd[*]: Accepted publickey for admin",
        "message": "sshd[*]: Accepted publickey for admin",
    }


def _patched_drain3(template_id_col: list[int], template_str_col: list[str]):
    """Return a mock for _run_drain3 that injects pre-set template columns."""
    def _mock(df: pd.DataFrame, *args, **kwargs) -> pd.DataFrame:
        df = df.copy()
        df["template_id"]  = template_id_col
        df["template_str"] = template_str_col
        return df
    return _mock


# ── Burst-collapse helpers ────────────────────────────────────────────────────
# _collapse_bursts works on the RARE set - a frame carrying the canonical
# `program` column (NOT _make_df, which restricts to ts/host/raw/message) plus
# the template columns _score_rarity would have added.

def _rare_row(
    ts: float, host: str, raw: str, *,
    program: str = "prog", template_id: int = 1, template_str: str = "t",
    message: str = "m",
) -> dict:
    return {
        "ts": ts, "host": host, "program": program, "raw": raw,
        "message": message, "template_id": template_id, "template_str": template_str,
    }


def _rare_df(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(
        rows,
        columns=["ts", "host", "program", "raw", "message", "template_id", "template_str"],
    )


def _collapse_parts(rows, *, gap=60, size=3):
    """Run the burst-only seam and expose both committed return members."""
    df = _rare_df(rows)
    pairs, remainder = _collapse_bursts(
        df, gap_seconds=gap, min_size=size,
        now=_NOW, data_window=_WINDOW,
    )
    return [f for _, f in pairs], remainder


def _collapse(rows, *, gap=60, size=3):
    """Unwrap only burst Findings for burst-evidence characterization tests."""
    return _collapse_parts(rows, gap=gap, size=size)[0]


def _family_fold(df: pd.DataFrame, *, min_size=2, threshold=1):
    """Run the family seam over a hand-built isolated remainder."""
    freq = {
        int(template_id): int(count)
        for template_id, count in df["template_id"].value_counts().items()
    }
    return _collapse_families(
        df, freq, threshold, min_size=min_size,
        now=_NOW, data_window=_WINDOW,
    )


def _run_with(rows: list[dict], ids: list[int], strs: list[str], cfg: dict | None = None):
    """Run the full detector with drain3 patched to a known template split."""
    df = pd.DataFrame(rows)
    with patch("sigwood.detectors.syslog._run_drain3", _patched_drain3(ids, strs)):
        return run(_ctx(df, cfg or {"max_count": 1, "rarity_pct": 10}))


# ── Reboot-channel helpers ────────────────────────────────────────────────────

def _reboot_df(triples) -> pd.DataFrame:
    """Build a reboot-signal frame (the df[reboot_mask] slice shape) from
    (ts, host, raw) triples for _detect_boot_events."""
    return pd.DataFrame([{"ts": ts, "host": host, "raw": raw} for ts, host, raw in triples])


def _make_burst_pair(host: str, start: float, end: float) -> tuple[float, Finding]:
    """A minimal (sort_ts, Finding) burst pair for _reconcile - carries only the
    keys _reconcile reads (tier / title / start_ts / end_ts / label)."""
    f = Finding(
        detector="syslog", severity=Severity.INFO, title=host, description="",
        evidence={"tier": "burst", "start_ts": start, "end_ts": end,
                  "line_count": 3, "label": None},
        next_steps=[], ts_generated=_NOW, data_window=_WINDOW,
    )
    return (start, f)


# ── Tests ─────────────────────────────────────────────────────────────────────

class SyslogDetectorTests(unittest.TestCase):

    # ── Constants ─────────────────────────────────────────────────────────────

    def test_status_and_name_constants(self) -> None:
        self.assertEqual(STATUS, "available")
        self.assertEqual(DETECTOR_NAME, "syslog")

    # ── Empty input ───────────────────────────────────────────────────────────

    def test_run_returns_empty_on_empty_dataframe(self) -> None:
        empty = _make_df([])
        self.assertEqual(run(_ctx(empty)), [])

    def test_run_returns_empty_when_logs_key_absent(self) -> None:
        ctx = DetectorContext(
            logs={},
            config={},
            allowlist=None,
            data_window=_WINDOW,
        )
        self.assertEqual(run(ctx), [])

    # ── Anomalous findings ────────────────────────────────────────────────────

    def test_run_returns_medium_findings_for_anomalous_rows(self) -> None:
        """One rare template (count=1) among 50 common rows → one MEDIUM finding."""
        rows = [_common_row(i) for i in range(50)]
        rows.append({
            "ts":      _BASE_TS + 3600.0,
            "host":    "192.0.2.1",
            "raw":     "<30>May 30 13:00:00 192.0.2.1 kernel: RARE_SENTINEL xyzzy_anomaly",
            "message": "kernel: RARE_SENTINEL xyzzy_anomaly",
        })
        df = _make_df(rows)

        # template_id=1 for 50 common rows, template_id=2 for the rare row
        ids  = [1] * 50 + [2]
        strs = ["sshd[*]: Accepted publickey for admin"] * 50 + ["kernel: RARE_SENTINEL <*>"]

        with patch("sigwood.detectors.syslog._run_drain3", _patched_drain3(ids, strs)):
            findings = run(_ctx(df, {"max_count": 1, "rarity_pct": 10}))

        assert_report_voice(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector, "syslog")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_rarity_pct_is_inert_at_max_count_1(self) -> None:
        """Characterization: rarity_pct is a decoy at the shipped max_count=1.

        threshold = min(percentile, max_count), so at max_count=1 the rare set is
        exactly the globally-singleton templates and rarity_pct has no effect -
        varying it (10 vs 50) does NOT change the flagged set. rarity_pct becomes
        live only once max_count is raised above the percentile-derived count; the
        second assertion drives the SAME fixture past that floor so the equality
        above reads as a property of the min() gate, not an empty-set coincidence.
        Documents the interaction; no scoring change.
        """
        # Four templates with distinct GLOBAL counts: t1=50 (common), t2=3, t3=2,
        # t4=1 (singleton). Rare rows are spaced an hour apart so burst-collapse
        # never folds them, and every row gets a distinct program so the new family
        # fold cannot erase this test's subject: the rarity gate and template ids.
        rows: list[dict] = []
        ids: list[int] = []
        strs: list[str] = []

        def _add(tid: int, ts: float, tag: str) -> None:
            rows.append({
                "ts": ts, "host": "192.0.2.1",
                "program": f"fixture-program-{len(rows)}",
                "raw": f"<30>May 30 12:00:00 192.0.2.1 {tag}",
                "message": f"{tag} <*>",
            })
            ids.append(tid)
            strs.append(f"{tag} <*>")

        for i in range(50):
            _add(1, _BASE_TS + i * 60.0, f"common-{i}")
        for i in range(3):
            _add(2, _BASE_TS + 100_000 + i * 3600.0, f"t2-{i}")
        for i in range(2):
            _add(3, _BASE_TS + 200_000 + i * 3600.0, f"t3-{i}")
        _add(4, _BASE_TS + 300_000, "t4-singleton")

        def _flagged(cfg: dict) -> list[int]:
            findings = _run_with(rows, ids, strs, cfg)
            return sorted(
                f.evidence["template_id"] for f in findings if "template_id" in f.evidence
            )

        # Decoy: identical flagged set for rarity_pct 10 vs 50 at max_count=1.
        self.assertEqual(
            _flagged({"max_count": 1, "rarity_pct": 10}),
            _flagged({"max_count": 1, "rarity_pct": 50}),
        )
        # Non-vacuity: the SAME fixture diverges once max_count is raised above the
        # percentile count, so rarity_pct is genuinely live there.
        self.assertNotEqual(
            _flagged({"max_count": 3, "rarity_pct": 10}),
            _flagged({"max_count": 3, "rarity_pct": 50}),
        )

    def test_medium_finding_evidence_fields(self) -> None:
        """Evidence contains host, template_id (int), template_str, count, threshold."""
        rows = [_common_row(i) for i in range(50)]
        rows.append({
            "ts":      _BASE_TS + 3600.0,
            "host":    "192.0.2.2",
            "raw":     "<30>May 30 13:00:00 192.0.2.2 cron[*]: Evidence fields test",
            "message": "cron[*]: Evidence fields test",
        })
        df = _make_df(rows)
        ids  = [1] * 50 + [99]
        strs = ["sshd[*]: Accepted publickey for admin"] * 50 + ["cron[*]: Evidence <*> test"]

        with patch("sigwood.detectors.syslog._run_drain3", _patched_drain3(ids, strs)):
            findings = run(_ctx(df, {"max_count": 1, "rarity_pct": 10}))

        self.assertEqual(len(findings), 1)
        ev = findings[0].evidence
        self.assertEqual(ev["host"], "192.0.2.2")
        self.assertIsInstance(ev["template_id"], int)
        self.assertIsInstance(ev["count"], int)
        self.assertIsInstance(ev["threshold"], int)
        self.assertIn("template_str", ev)

    # ── Burst collapse - grouping semantics ───────────────────────────────────

    def test_collapse_groups_per_host_not_cross_host(self) -> None:
        rows = (
            [_rare_row(_BASE_TS + i, "host-a", f"a{i}", template_id=i) for i in range(3)]
            + [_rare_row(_BASE_TS + i, "host-b", f"b{i}", template_id=10 + i) for i in range(3)]
        )
        bursts, remainder = _collapse_parts(rows)
        self.assertEqual(len(bursts), 2)
        self.assertTrue(remainder.empty)
        self.assertEqual({f.title for f in bursts}, {"host-a", "host-b"})
        self.assertTrue(all(f.evidence["line_count"] == 3 for f in bursts))

    def test_collapse_gap_exactly_equal_splits(self) -> None:
        # Neighbour gaps of EXACTLY gap_seconds split → three singletons, no burst.
        rows = [_rare_row(_BASE_TS + i * 60, "h", f"r{i}", template_id=i) for i in range(3)]
        bursts, remainder = _collapse_parts(rows, gap=60, size=3)
        self.assertEqual(bursts, [])
        self.assertEqual(remainder["raw"].tolist(), ["r0", "r1", "r2"])

    def test_collapse_gap_below_threshold_merges(self) -> None:
        rows = [_rare_row(_BASE_TS + i * 59, "h", f"r{i}", template_id=i) for i in range(3)]
        bursts, remainder = _collapse_parts(rows, gap=60, size=3)
        self.assertEqual(len(bursts), 1)
        self.assertTrue(remainder.empty)
        self.assertEqual(bursts[0].evidence["line_count"], 3)

    def test_collapse_size_boundary_two_isolated_three_burst(self) -> None:
        two = [_rare_row(_BASE_TS + i, "h", f"r{i}", template_id=i) for i in range(2)]
        f2, r2 = _collapse_parts(two, gap=60, size=3)
        self.assertEqual(f2, [])
        self.assertEqual(r2["raw"].tolist(), ["r0", "r1"])
        three = [_rare_row(_BASE_TS + i, "h", f"r{i}", template_id=i) for i in range(3)]
        f3, r3 = _collapse_parts(three, gap=60, size=3)
        self.assertEqual(len(f3), 1)
        self.assertTrue(r3.empty)

    def test_collapse_nan_ts_never_bursts(self) -> None:
        rows = [_rare_row(float("nan"), "h", f"n{i}", template_id=i) for i in range(5)]
        bursts, remainder = _collapse_parts(rows, gap=60, size=3)
        self.assertEqual(bursts, [])
        self.assertEqual(remainder["raw"].tolist(), [f"n{i}" for i in range(5)])
        self.assertTrue(remainder["ts"].isna().all())

    # ── Burst collapse - reboot handling ──────────────────────────────────────

    def test_reconcile_labels_contemporaneous_burst(self) -> None:
        # _collapse_bursts never labels a burst (label is always None); _reconcile
        # is the SOLE writer of "rebooted", and only for a boot event
        # contemporaneous with the burst (within burst_gap_seconds), emitting no
        # standalone for the labeled event.
        rows = [_rare_row(_BASE_TS + i, "h", f"r{i}", program="cron", template_id=i)
                for i in range(3)]
        burst_pairs, remainder = _collapse_bursts(
            _rare_df(rows),
            gap_seconds=60, min_size=3, now=_NOW, data_window=_WINDOW,
        )
        self.assertEqual(len(burst_pairs), 1)
        self.assertTrue(remainder.empty)
        self.assertIsNone(burst_pairs[0][1].evidence["label"])  # unlabeled from the pass

        evt = _BootEvent("h", _BASE_TS + 1, _BASE_TS + 1, 1)   # inside the burst span
        out = _reconcile([evt], burst_pairs, gap_seconds=60, now=_NOW, data_window=_WINDOW)
        labeled = [f for _, f in out if f.evidence.get("tier") == "burst"]
        self.assertEqual(len(labeled), 1)
        self.assertEqual(labeled[0].evidence["label"], "rebooted")
        self.assertFalse([f for _, f in out if f.evidence.get("tier") == "reboot"])  # no standalone

    def test_collapse_burst_without_reboot_label_none_key_present(self) -> None:
        rows = [_rare_row(_BASE_TS + i, "h", f"r{i}", program="cron", template_id=i)
                for i in range(3)]
        b = [f for f in _collapse(rows)
             if f.evidence.get("tier") == "burst"][0]
        self.assertIsNone(b.evidence["label"])
        self.assertIn("label", b.evidence)  # key ALWAYS present

    def test_run_isolated_reboot_is_standalone_info_not_medium(self) -> None:
        # A lone reboot row through the FULL detector path surfaces as a
        # standalone INFO reboot, never a MEDIUM needle - the full-frame reboot
        # channel catches it and excludes it from the rare set. Asserted against
        # run() (the & ~reboot_mask guarantee), NOT _collapse_bursts directly:
        # that helper classifies only the rare NON-reboot set, so a reboot row
        # fed to it directly would (correctly) become a MEDIUM needle - the
        # invariant is a property of the detector, not the helper.
        reboot = [{"ts": _BASE_TS, "host": "192.0.2.1", "program": "systemd-logind",
                   "raw": "systemd-logind[1]: System is rebooting.",
                   "message": "systemd-logind: System is rebooting."}]
        findings = _run_with(reboot, [1], ["reboot_t"])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, Severity.INFO)
        self.assertEqual(f.evidence["tier"], "reboot")
        self.assertEqual(f.evidence["label"], "rebooted")
        self.assertEqual(f.evidence["signal_count"], 1)
        self.assertEqual(f.title, "192.0.2.1")
        self.assertTrue(f.evidence["reboot_ts"].endswith("+00:00"))  # aware ISO UTC

    # ── Burst collapse - invariants & shapes ──────────────────────────────────

    def test_collapse_conserves_every_rare_non_reboot_row(self) -> None:
        # _collapse_bursts runs on the rare set AFTER reboot rows are excluded
        # (run() drops them via ~reboot_mask), so burst members plus the literal
        # remainder conserve every rare NON-reboot row exactly once.
        rows = (
            [_rare_row(_BASE_TS + i, "host-a", f"a{i}", program="kernel", template_id=2)
             for i in range(5)]
            + [_rare_row(_BASE_TS, "host-b", "lone", template_id=99)]
        )
        bursts, remainder = _collapse_parts(rows)
        burst_lines = sum(f.evidence["line_count"] for f in bursts)
        self.assertEqual(burst_lines + len(remainder), len(rows))

    def test_collapse_empty_returns_empty(self) -> None:
        pairs, remainder = _collapse_bursts(
            _rare_df([]), gap_seconds=60, min_size=3,
            now=_NOW, data_window=_WINDOW,
        )
        self.assertEqual(pairs, [])
        self.assertTrue(remainder.empty)
        self.assertEqual(list(remainder.columns), list(_rare_df([]).columns))

    def test_collapse_remainder_does_not_expand_duplicate_source_indexes(self) -> None:
        df = _rare_df([
            _rare_row(_BASE_TS, "h", "first", template_id=1),
            _rare_row(_BASE_TS + 120, "h", "second", template_id=2),
        ])
        df.index = [7, 7]
        pairs, remainder = _collapse_bursts(
            df, gap_seconds=60, min_size=3, now=_NOW, data_window=_WINDOW,
        )
        self.assertEqual(pairs, [])
        self.assertEqual(remainder["raw"].tolist(), ["first", "second"])

    def test_collapse_program_mix_top3_deterministic(self) -> None:
        rows = (
            [_rare_row(_BASE_TS + i, "h", f"r{i}", program="aaa", template_id=i) for i in range(3)]
            + [_rare_row(_BASE_TS + 3, "h", "x", program="bbb", template_id=10)]
            + [_rare_row(_BASE_TS + 4, "h", "y", program="ccc", template_id=11)]
            + [_rare_row(_BASE_TS + 5, "h", "z", program="ddd", template_id=12)]
        )
        b = [f for f in _collapse(rows)
             if f.evidence.get("tier") == "burst"][0]
        pm = b.evidence["program_mix"]
        self.assertEqual(len(pm), 3)          # top-3 cap
        self.assertEqual(pm[0], ["aaa", 3])   # highest count first; list[[str,int]]

    def test_collapse_sample_raw_capped_line_count_exact(self) -> None:
        rows = [_rare_row(_BASE_TS + i, "h", f"r{i}", program="p", template_id=i)
                for i in range(25)]
        b = [f for f in _collapse(rows)
             if f.evidence.get("tier") == "burst"][0]
        self.assertEqual(b.evidence["line_count"], 25)        # exact
        self.assertEqual(len(b.evidence["sample_raw"]), 20)   # capped sample

    def test_collapse_tie_ts_sample_is_input_order_deterministic(self) -> None:
        # All rows share one ts (a ring-buffer flush): the stable ts-sort keeps
        # input order, so WHICH 20 survive the cap (and their order) is fixed and
        # version-independent - not at the mercy of quicksort tie handling.
        rows = [_rare_row(_BASE_TS, "h", f"line-{i:02d}", program="p", template_id=i)
                for i in range(25)]
        b = [f for f in _collapse(rows)
             if f.evidence.get("tier") == "burst"][0]
        self.assertEqual(b.evidence["sample_raw"], [f"line-{i:02d}" for i in range(20)])

    def test_collapse_missing_program_column_coerces_unknown(self) -> None:
        # A frame lacking `program` (the minimal shape) must not raise;
        # program coerces to the "unknown" sentinel (govern-don't-grep robustness).
        df = pd.DataFrame(
            [{"ts": _BASE_TS + i, "host": "h", "raw": f"r{i}", "message": "m",
              "template_id": i, "template_str": "t"} for i in range(3)]
        )
        pairs, remainder = _collapse_bursts(
            df, gap_seconds=60, min_size=3, now=_NOW, data_window=_WINDOW,
        )
        bursts = [f for _, f in pairs if f.evidence.get("tier") == "burst"]
        self.assertEqual(len(bursts), 1)
        self.assertTrue(remainder.empty)
        self.assertEqual(bursts[0].evidence["program_mix"], [["unknown", 3]])

    def test_collapse_keeps_nan_host_rows(self) -> None:
        # pandas groupby drops NaN keys by default; the detector normalizes host
        # to "unknown" first, so a NaN-host rare row still produces a finding.
        df = pd.DataFrame(
            [{"ts": _BASE_TS, "host": float("nan"), "program": "p", "raw": "r",
              "message": "m", "template_id": 1, "template_str": "t"}]
        )
        pairs, remainder = _collapse_bursts(
            df, gap_seconds=60, min_size=3, now=_NOW, data_window=_WINDOW,
        )
        self.assertEqual(pairs, [])
        self.assertEqual(len(remainder), 1)
        self.assertEqual(remainder.iloc[0]["host"], "unknown")

    def test_curated_reboot_is_label_and_signal_count_and_burst_excludes_bulk(self) -> None:
        from sigwood.outputs._evidence import curated_evidence
        reboot = _reboot_finding(_BootEvent("h", _BASE_TS, _BASE_TS, 2), _NOW, _WINDOW)[1]
        self.assertEqual(curated_evidence(reboot), {"label": "rebooted", "signal_count": 2})
        # A rebooted burst (labeled by _reconcile) keeps its label in curated;
        # the bulky/structural keys stay out of the worklist.
        storm = [
            _rare_row(_BASE_TS + i, "h", f"s{i}", program="systemd", template_id=2 + i)
            for i in range(3)
        ]
        burst_pairs, remainder = _collapse_bursts(
            _rare_df(storm),
            gap_seconds=60, min_size=3, now=_NOW, data_window=_WINDOW,
        )
        self.assertTrue(remainder.empty)
        out = _reconcile([_BootEvent("h", _BASE_TS, _BASE_TS, 1)], burst_pairs,
                         gap_seconds=60, now=_NOW, data_window=_WINDOW)
        b = [f for _, f in out if f.evidence.get("tier") == "burst"][0]
        cur = curated_evidence(b)
        self.assertEqual(set(cur), {"line_count", "span_seconds", "program_mix", "label"})
        self.assertEqual(cur["label"], "rebooted")
        self.assertIsInstance(cur["program_mix"], str)  # stringified for the worklist
        for k in ("sample_raw", "start_ts", "end_ts"):
            self.assertNotIn(k, cur)  # bulky / structural keys are not worklist cells

    def test_burst_program_mix_json_shape_is_list_of_str_int(self) -> None:
        from sigwood.outputs._serialize import to_jsonable
        rows = [_rare_row(_BASE_TS + i, "h", f"r{i}",
                          program="prog-a" if i < 2 else "prog-b", template_id=i)
                for i in range(3)]
        b = [f for f in _collapse(rows)
             if f.evidence.get("tier") == "burst"][0]
        pm = to_jsonable(b.evidence["program_mix"])
        self.assertIsInstance(pm, list)
        self.assertTrue(all(isinstance(x, list) and len(x) == 2
                            and isinstance(x[0], str) and isinstance(x[1], int) for x in pm))

    # ── Family fold ───────────────────────────────────────────────────────────

    def test_family_groups_by_host_and_program_with_prescribed_shape(self) -> None:
        rows = [
            _rare_row(_BASE_TS, "host-a", "a0", program="sshd", template_id=1),
            _rare_row(_BASE_TS + 120, "host-a", "a1", program="sshd", template_id=2),
            _rare_row(_BASE_TS + 240, "host-a", "a2", program="kernel", template_id=3),
            _rare_row(_BASE_TS + 360, "host-b", "b0", program="sshd", template_id=4),
        ]
        pairs = _family_fold(_rare_df(rows))
        families = [f for _, f in pairs if f.evidence.get("tier") == "family"]
        needles = [f for _, f in pairs if f.evidence.get("tier") is None]

        self.assertEqual(len(families), 1)
        self.assertEqual(len(needles), 2)
        family = families[0]
        self.assertEqual(family.severity, Severity.MEDIUM)
        self.assertEqual(family.title, "host-a")
        self.assertEqual(family.evidence, {
            "tier": "family",
            "host": "host-a",
            "program": "sshd",
            "line_count": 2,
            "start_ts": _BASE_TS,
            "end_ts": _BASE_TS + 120,
            "span_seconds": 120.0,
            "sample_raw": ["a0", "a1"],
            "label": None,
        })
        self.assertEqual(
            family.description,
            "A set of rare log lines from a single program on this host, each at or "
            "below the rarity threshold.",
        )
        self.assertEqual(
            family.next_steps,
            ["Skim the sampled lines to confirm the cluster's cause"],
        )
        assert_report_voice([family])

    def test_family_samples_chronological_nan_last_and_caps_at_twenty(self) -> None:
        rows = [
            _rare_row(
                float("nan") if i in (0, 23) else _BASE_TS + (24 - i),
                "h", f"line-{i:02d}", program="p", template_id=i,
            )
            for i in range(25)
        ]
        pair = _family_fold(_rare_df(rows))[0]
        family = pair[1]
        self.assertEqual(pair[0], _BASE_TS)
        self.assertEqual(family.evidence["line_count"], 25)
        self.assertEqual(family.evidence["start_ts"], _BASE_TS)
        self.assertEqual(family.evidence["end_ts"], _BASE_TS + 23)
        self.assertEqual(family.evidence["span_seconds"], 23.0)
        self.assertEqual(len(family.evidence["sample_raw"]), 20)
        self.assertEqual(family.evidence["sample_raw"][0], "line-24")
        self.assertNotIn("line-00", family.evidence["sample_raw"])  # NaN rows sort last

    def test_family_all_nan_timestamps_use_none_and_infinite_sort(self) -> None:
        rows = [
            _rare_row(float("nan"), "h", "first", program="p", template_id=1),
            _rare_row(float("nan"), "h", "second", program="p", template_id=2),
        ]
        sort_ts, family = _family_fold(_rare_df(rows))[0]
        self.assertEqual(sort_ts, float("inf"))
        self.assertIsNone(family.evidence["start_ts"])
        self.assertIsNone(family.evidence["end_ts"])
        self.assertIsNone(family.evidence["span_seconds"])
        self.assertEqual(family.evidence["sample_raw"], ["first", "second"])

    def test_family_mixed_timestamps_sample_nan_last(self) -> None:
        rows = [
            _rare_row(float("nan"), "h", "undated", program="p", template_id=1),
            _rare_row(_BASE_TS + 20, "h", "later", program="p", template_id=2),
            _rare_row(_BASE_TS + 10, "h", "earlier", program="p", template_id=3),
        ]
        _, family = _family_fold(_rare_df(rows))[0]
        self.assertEqual(
            family.evidence["sample_raw"], ["earlier", "later", "undated"]
        )
        self.assertEqual(family.evidence["start_ts"], _BASE_TS + 10)
        self.assertEqual(family.evidence["end_ts"], _BASE_TS + 20)
        self.assertEqual(family.evidence["span_seconds"], 10.0)

    def test_family_min_size_one_characterized(self) -> None:
        row = _rare_row(_BASE_TS, "h", "one", program="p", template_id=1)
        sort_ts, finding = _family_fold(_rare_df([row]), min_size=1)[0]
        self.assertEqual(sort_ts, _BASE_TS)
        self.assertEqual(finding.evidence["tier"], "family")
        self.assertEqual(finding.evidence["line_count"], 1)

    def test_family_of_one_preserves_level_zero_and_verbose_one(self) -> None:
        from sigwood.outputs._render_model import _partition_syslog
        from sigwood.outputs.text import TextHandler

        row = _rare_row(_BASE_TS, "h", "raw-one", program="sshd", template_id=1)
        finding = _family_fold(_rare_df([row]))[0][1]
        legacy = Finding(
            detector=finding.detector,
            severity=finding.severity,
            title=finding.title,
            description=finding.description,
            evidence={k: v for k, v in finding.evidence.items() if k != "program"},
            next_steps=finding.next_steps,
            ts_generated=finding.ts_generated,
            data_window=finding.data_window,
        )

        for level in (0, 1):
            current = TextHandler(verbose_level=level)._render_syslog_group(
                _partition_syslog([finding])
            )
            before = TextHandler(verbose_level=level)._render_syslog_group(
                _partition_syslog([legacy])
            )
            self.assertEqual(current, before)

        debug = "\n".join(
            TextHandler(verbose_level=2)._render_syslog_group(
                _partition_syslog([finding])
            )
        )
        self.assertIn("program: sshd", debug)

    def test_family_pipeline_represents_every_row_exactly_once_with_program_defenses(self) -> None:
        base_rows = (
            [_rare_row(_BASE_TS + i, "burst-host", f"burst-{i}", template_id=i)
             for i in range(3)]
            + [_rare_row(_BASE_TS + i * 120, "family-host", f"family-{i}", template_id=10 + i)
               for i in range(2)]
            + [_rare_row(_BASE_TS + 500, "needle-host", "needle", template_id=20)]
            + [_rare_row(float("nan"), "nan-host", f"nan-{i}", template_id=30 + i)
               for i in range(2)]
        )
        frames = [
            _rare_df(base_rows).drop(columns=["program"]),
            _rare_df([
                {**row, "program": None if row["host"] in ("family-host", "nan-host")
                 else row["program"]}
                for row in base_rows
            ]),
        ]

        for frame in frames:
            burst_pairs, remainder = _collapse_bursts(
                frame, gap_seconds=60, min_size=3,
                now=_NOW, data_window=_WINDOW,
            )
            family_pairs = _family_fold(remainder)
            findings = [f for _, f in [*burst_pairs, *family_pairs]]
            represented: list[str] = []
            for finding in findings:
                if finding.evidence.get("tier") in ("burst", "family"):
                    represented.extend(finding.evidence["sample_raw"])
                else:
                    represented.append(finding.title)
            self.assertEqual(
                Counter(represented),
                Counter(str(raw) for raw in frame["raw"]),
            )

    def test_reconcile_never_labels_family_and_emits_standalone_reboot(self) -> None:
        rows = [
            _rare_row(_BASE_TS, "h", "f0", program="p", template_id=1),
            _rare_row(_BASE_TS + 120, "h", "f1", program="p", template_id=2),
        ]
        family_pair = _family_fold(_rare_df(rows))[0]
        out = _reconcile(
            [_BootEvent("h", _BASE_TS + 1, _BASE_TS + 1, 1)],
            [family_pair], gap_seconds=60, now=_NOW, data_window=_WINDOW,
        )
        family = [f for _, f in out if f.evidence.get("tier") == "family"][0]
        reboots = [f for _, f in out if f.evidence.get("tier") == "reboot"]
        self.assertIsNone(family.evidence["label"])
        self.assertEqual(len(reboots), 1)

    # ── End-to-end fixtures (a)-(d) via run() with drain3 patched ─────────────

    def test_run_boot_storm_collapses_to_one_labeled_burst(self) -> None:
        common = [_common_row(i) for i in range(50)]
        storm = [
            {"ts": _BASE_TS + 100000 + j, "host": "192.0.2.1", "program": p,
             "raw": r, "message": r}
            for j, (p, r) in enumerate([
                ("kernel", "kernel: [    0.000000] Linux version 6.1"),  # ring-buffer banner
                ("systemd", "systemd: Starting service"),
                ("kernel", "kernel: ACPI subsystem"),
                ("NetworkManager", "NetworkManager: device up"),
            ])
        ]
        ids  = [1] * 50 + [2, 3, 4, 5]
        strs = ["common"] * 50 + ["b2", "b3", "b4", "b5"]
        result = _run_with(common + storm, ids, strs)
        bursts = [f for f in result if f.evidence.get("tier") == "burst"]
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0].severity, Severity.INFO)
        # line_count is 3, NOT 4: the kernel banner leaves rare_df via ~reboot_mask,
        # so the burst counts the non-reboot rare rows only.
        self.assertEqual(bursts[0].evidence["line_count"], 3)
        self.assertEqual(bursts[0].evidence["label"], "rebooted")  # labeled by _reconcile
        # Exactly ONE representation: the labeled burst, no separate standalone reboot.
        self.assertFalse([f for f in result if f.evidence.get("tier") == "reboot"])

    def test_run_variable_length_lines_collapse_to_one_burst(self) -> None:
        common = [_common_row(i) for i in range(50)]
        hexdump = [
            {"ts": _BASE_TS + 100000 + j, "host": "192.0.2.5", "program": "pam_u2f",
             "raw": "pam_u2f: " + "ab" * (j + 1), "message": f"hx{j}"}
            for j in range(6)
        ]
        ids  = [1] * 50 + [2, 3, 4, 5, 6, 7]
        strs = ["common"] * 50 + [f"hx{j}" for j in range(6)]
        bursts = [f for f in _run_with(common + hexdump, ids, strs)
                  if f.evidence.get("tier") == "burst"]
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0].evidence["line_count"], 6)
        self.assertIsNone(bursts[0].evidence["label"])

    def test_run_far_apart_same_program_folds_seeded_needles_into_family(self) -> None:
        common = [_common_row(i) for i in range(50)]
        seeded = [
            {"ts": _BASE_TS + 100_000, "host": "192.0.2.7", "program": "sshd",
             "raw": "sshd: privileged login sentinel", "message": "privileged login sentinel"},
            {"ts": _BASE_TS + 101_000, "host": "192.0.2.7", "program": "sshd",
             "raw": "sshd: persistence sentinel", "message": "persistence sentinel"},
        ]
        ids = [1] * 50 + [2, 3]
        strs = ["common"] * 50 + ["privileged login sentinel", "persistence sentinel"]

        result = _run_with(common + seeded, ids, strs)
        families = [f for f in result if f.evidence.get("tier") == "family"]
        self.assertEqual(len(families), 1)
        self.assertEqual(families[0].evidence["line_count"], 2)
        self.assertEqual(
            families[0].evidence["sample_raw"],
            ["sshd: privileged login sentinel", "sshd: persistence sentinel"],
        )
        self.assertFalse([f for f in result if f.evidence.get("tier") is None])

    def test_run_clean_reboot_no_storm_is_standalone_reboot(self) -> None:
        common = [_common_row(i) for i in range(50)]
        reboot = [{"ts": _BASE_TS + 100000, "host": "192.0.2.1",
                   "program": "systemd-logind",
                   "raw": "systemd-logind[1]: System is rebooting.",
                   "message": "systemd-logind: System is rebooting."}]
        ids  = [1] * 50 + [2]
        strs = ["common"] * 50 + ["reboot_t"]
        findings = _run_with(common + reboot, ids, strs)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["tier"], "reboot")
        self.assertEqual(findings[0].severity, Severity.INFO)
        self.assertEqual(findings[0].title, "192.0.2.1")
        self.assertEqual(findings[0].evidence["signal_count"], 1)

    # ── Reboot full-frame channel ─────────────────────────────────────────────

    def test_run_repeated_reboot_template_surfaces_every_boot(self) -> None:
        # THE REGRESSION GUARD. A reboot banner whose drain3 template repeats
        # across boots (count >= 2) is NOT rare, so the rarity-gated path surfaced
        # only one boot and hid the rest. The full-frame mask is rarity-blind: N
        # boots that share ONE template AND are spaced beyond reboot_cluster_seconds
        # each surface a reboot, and none leak as MEDIUM needles.
        n = 4
        common = [_common_row(i) for i in range(50)]
        reboots = [{"ts": _BASE_TS + 100000 + k * 3600, "host": "192.0.2.1",
                    "program": "systemd-logind",
                    "raw": "systemd-logind[1]: System is rebooting.",
                    "message": "systemd-logind: System is rebooting."}
                   for k in range(n)]
        ids  = [1] * 50 + [9] * n            # ALL reboots share template 9 -> count n, NOT rare
        strs = ["common"] * 50 + ["rb"] * n
        result = _run_with(common + reboots, ids, strs)
        reboots_found = [f for f in result if f.evidence.get("tier") == "reboot"]
        self.assertEqual(len(reboots_found), n)
        self.assertTrue(all(f.severity == Severity.INFO for f in reboots_found))
        # N DISTINCT single-signal boots, not one merged event: proves the 3600s
        # spacing survives the 600s clustering (the "distinct events" half).
        self.assertTrue(all(f.evidence["signal_count"] == 1 for f in reboots_found))
        self.assertFalse([f for f in result if f.evidence.get("tier") is None])  # no MEDIUM leak

    def test_detect_boot_events_intra_reboot_gap_over_60s_is_one_event(self) -> None:
        # One reboot can fire several signals more than burst_gap_seconds (60s)
        # apart, so they cluster on their own wider window - a ~75s gap the 60s
        # burst gap would split stays ONE boot event under reboot_cluster_seconds.
        df = _reboot_df([
            (_BASE_TS, "h", "systemd-logind[1]: System is rebooting."),
            (_BASE_TS + 75, "h", "kernel: [    0.000000] Linux version 6.1"),
        ])
        events = _detect_boot_events(df, cluster_seconds=REBOOT_CLUSTER_SECONDS)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].signal_count, 2)
        self.assertEqual(events[0].start_ts, _BASE_TS)
        self.assertEqual(events[0].end_ts, _BASE_TS + 75)

    def test_detect_boot_events_distinct_reboots_beyond_window_are_two(self) -> None:
        df = _reboot_df([
            (_BASE_TS, "h", "systemd-logind[1]: System is rebooting."),
            (_BASE_TS + 700, "h", "systemd-logind[1]: System is rebooting."),
        ])
        events = _detect_boot_events(df, cluster_seconds=REBOOT_CLUSTER_SECONDS)
        self.assertEqual(len(events), 2)

    def test_reconcile_distinct_events_claim_at_most_one_burst(self) -> None:
        # Two distinct boot events: only the contemporaneous one claims the burst;
        # the far event stands alone. A burst is claimed at most once.
        burst_rows = [_rare_row(_BASE_TS + i, "h", f"r{i}", program="p", template_id=i)
                      for i in range(3)]
        burst_pairs, remainder = _collapse_bursts(
            _rare_df(burst_rows), gap_seconds=60, min_size=3,
            now=_NOW, data_window=_WINDOW,
        )
        self.assertTrue(remainder.empty)
        near = _BootEvent("h", _BASE_TS + 1, _BASE_TS + 1, 1)         # inside the burst span
        far  = _BootEvent("h", _BASE_TS + 5000, _BASE_TS + 5000, 1)   # far away
        out = _reconcile([near, far], burst_pairs, gap_seconds=60, now=_NOW, data_window=_WINDOW)
        labeled = [f for _, f in out if f.evidence.get("tier") == "burst"]
        standalone = [f for _, f in out if f.evidence.get("tier") == "reboot"]
        self.assertEqual(len(labeled), 1)
        self.assertEqual(labeled[0].evidence["label"], "rebooted")    # claimed by `near`
        self.assertEqual(len(standalone), 1)                          # `far` stands alone

    def test_detect_boot_events_all_nan_ts_is_one_indeterminate_event(self) -> None:
        df = _reboot_df([
            (float("nan"), "h", "systemd-logind[1]: System is rebooting."),
            (float("nan"), "h", "rsyslogd: [origin] exiting on signal 15"),
        ])
        events = _detect_boot_events(df, cluster_seconds=REBOOT_CLUSTER_SECONDS)
        self.assertEqual(len(events), 1)               # bounded one-per-host
        self.assertIsNone(events[0].start_ts)          # indeterminate marker
        self.assertEqual(events[0].signal_count, 2)
        reboot = _reboot_finding(events[0], _NOW, _WINDOW)[1]
        self.assertIsNone(reboot.evidence["reboot_ts"])

    def test_detect_boot_events_empty_and_columnless(self) -> None:
        self.assertEqual(_detect_boot_events(pd.DataFrame(), cluster_seconds=600), [])
        self.assertEqual(
            _detect_boot_events(pd.DataFrame({"raw": ["x"]}), cluster_seconds=600), [])

    def test_detect_boot_events_nan_host_normalized(self) -> None:
        df = _reboot_df([(_BASE_TS, float("nan"), "systemd-logind[1]: System is rebooting.")])
        events = _detect_boot_events(df, cluster_seconds=600)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].host, "unknown")

    def test_boot_event_start_ts_zero_epoch_is_not_indeterminate(self) -> None:
        # 0.0 is a valid epoch and falsy: sort_ts / reboot_ts key on `is None`,
        # never truthiness, so a 1970 timestamp is NOT read as indeterminate.
        sort_ts, finding = _reboot_finding(_BootEvent("h", 0.0, 0.0, 1), _NOW, _WINDOW)
        self.assertEqual(sort_ts, 0.0)
        self.assertIsNotNone(finding.evidence["reboot_ts"])

    def test_reconcile_nearest_burst_tie_breaks_on_smaller_ss(self) -> None:
        # Two equidistant candidate bursts (abs(ss-bs) == 10 for both): the tie
        # breaks to the burst with the smaller start_ts.
        left  = _make_burst_pair("h", _BASE_TS - 10, _BASE_TS - 10)
        right = _make_burst_pair("h", _BASE_TS + 10, _BASE_TS + 10)
        # Pass the larger-ss burst FIRST so insertion order can't select the
        # winner: both are equidistant (abs(ss-bs) == 10), so ONLY the smaller-ss
        # tie-break can pick `left`.
        _reconcile([_BootEvent("h", _BASE_TS, _BASE_TS, 1)], [right, left],
                   gap_seconds=60, now=_NOW, data_window=_WINDOW)
        self.assertEqual(left[1].evidence["label"], "rebooted")   # smaller ss wins
        self.assertIsNone(right[1].evidence["label"])

    def test_reconcile_nan_ts_event_matches_no_burst(self) -> None:
        burst = _make_burst_pair("h", _BASE_TS, _BASE_TS + 5)
        out = _reconcile([_BootEvent("h", None, None, 2)], [burst],
                         gap_seconds=60, now=_NOW, data_window=_WINDOW)
        self.assertIsNone(burst[1].evidence["label"])                       # burst untouched
        self.assertEqual(len([f for _, f in out if f.evidence.get("tier") == "reboot"]), 1)

    def test_gap_cluster_strict_equal_splits(self) -> None:
        Row = namedtuple("Row", "ts")
        splits = _gap_cluster(iter([Row(_BASE_TS + i * 60) for i in range(3)]), 60)
        self.assertEqual([len(g) for g in splits], [1, 1, 1])   # gap == window -> split
        merged = _gap_cluster(iter([Row(_BASE_TS + i * 59) for i in range(3)]), 60)
        self.assertEqual([len(g) for g in merged], [3])         # gap < window -> merge

    def test_reboot_signals_regex_no_capturing_group_no_userwarning(self) -> None:
        self.assertEqual(REBOOT_SIGNALS_RE.groups, 0)
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            # would raise if str.contains emitted the capturing-group UserWarning
            pd.Series(["systemd-logind: System is rebooting", "nope"]).str.contains(
                REBOOT_SIGNALS_RE, na=False)
        # matches unchanged after the (?: edit (is_reboot_signal uses .search)
        for line in ("systemd-logind[1]: System is rebooting.",
                     "rsyslogd: [origin] exiting on signal 15",
                     "systemd-shutdown[1]: Sending SIGTERM to remaining processes",
                     "kernel: [    0.000000] Linux version 6.1"):
            self.assertTrue(is_reboot_signal(line))
        self.assertFalse(is_reboot_signal("sshd: Accepted publickey for admin"))

    def test_run_result_set_invariant_across_verbose_levels(self) -> None:
        # The detector output is verbosity-blind; the reading pipeline must not
        # DROP any syslog finding at any level (no level_visible rule for syslog).
        from sigwood.outputs._render_model import _build_renderable
        medium = Finding(detector="syslog", severity=Severity.MEDIUM, title="rare",
                         description="", evidence={"host": "h", "template_str": "t",
                         "count": 1, "threshold": 1}, next_steps=[],
                         ts_generated=_NOW, data_window=_WINDOW)
        burst = Finding(detector="syslog", severity=Severity.INFO, title="h",
                        description="", evidence={"tier": "burst", "line_count": 4,
                        "span_seconds": 1.0, "start_ts": 1.0, "end_ts": 2.0,
                        "program_mix": [["p", 4]], "sample_raw": ["a"], "label": None},
                        next_steps=[], ts_generated=_NOW, data_window=_WINDOW)
        family = Finding(detector="syslog", severity=Severity.MEDIUM, title="h",
                         description="", evidence={"tier": "family", "host": "h",
                         "program": "p", "line_count": 2, "start_ts": 3.0,
                         "end_ts": 4.0, "span_seconds": 1.0,
                         "sample_raw": ["b", "c"], "label": None},
                         next_steps=[], ts_generated=_NOW, data_window=_WINDOW)
        fs = [medium, family, burst]
        for lvl in (0, 1, 2):
            r = _build_renderable("syslog", fs, lvl, 100)
            self.assertEqual(sum(len(s.findings) for s in r.sections), len(fs))

    # ── Text renderer ─────────────────────────────────────────────────────────

    def test_text_renderer_syslog_group(self) -> None:
        """Two-section render: rare-event needles lead, then bursts; the reboot
        line is assembled from evidence, template/count details stay behind -v."""
        from sigwood.outputs.text import TextHandler
        from sigwood.outputs._render_model import _partition_syslog

        medium_f = Finding(
            detector="syslog",
            severity=Severity.MEDIUM,
            title="May 30 14:23:01 router sshd[100]: Failed password for root",
            description="Rare template",
            evidence={
                "host": "router", "template_id": 47,
                "template_str": "sshd[*]: Failed password for <*>",
                "count": 1, "threshold": 3,
            },
            next_steps=[],
            ts_generated=_NOW,
            data_window=_WINDOW,
        )
        reboot_f = Finding(
            detector="syslog",
            severity=Severity.INFO,
            title="host1",
            description="Reboot detected",
            evidence={
                "tier": "reboot", "host": "host1",
                "reboot_ts": "2026-05-30T02:14:00+00:00", "label": "rebooted",
            },
            next_steps=[],
            ts_generated=_NOW,
            data_window=_WINDOW,
        )

        handler = TextHandler(verbose_level=0)
        joined = "\n".join(
            handler._render_syslog_group(_partition_syslog([medium_f, reboot_f]))
        )

        # Section labels with pre-cap counts, rare events leading.
        self.assertIn("rare events (1)", joined)
        self.assertIn("bursts (1)", joined)
        self.assertLess(joined.index("rare events"), joined.index("bursts"))
        # MEDIUM needle: raw line, template/count internals stay behind -v.
        self.assertIn("May 30 14:23:01 router sshd[100]", joined)
        self.assertNotIn("count=", joined)
        self.assertNotIn("template_id", joined)
        # Reboot line assembled from evidence.
        self.assertIn("host1 · rebooted @ 2026-05-30T02:14:00+00:00", joined)

    def test_text_renderer_syslog_verbose_shows_template_details(self) -> None:
        """Verbose syslog output includes rarity and drain3 template internals."""
        from sigwood.outputs.text import TextHandler

        medium_f = Finding(
            detector="syslog",
            severity=Severity.MEDIUM,
            title="May 30 14:23:01 router sshd[100]: Failed password for root",
            description="Rare template",
            evidence={
                "host": "router", "template_id": 47,
                "template_str": "sshd[*]: Failed password for <*>",
                "count": 1, "threshold": 3,
            },
            next_steps=["Review surrounding log context for this host"],
            ts_generated=_NOW,
            data_window=_WINDOW,
        )

        rendered = "\n".join(
            TextHandler(verbose_level=1)._render_syslog_group(_flat_section([medium_f]))
        )

        self.assertIn("May 30 14:23:01 router sshd[100]", rendered)
        # curated subset for syslog (template): template_str, host, count, threshold.
        # template_id is internal - only surfaced under -vv (debug tail).
        self.assertIn("template_str: sshd[*]: Failed password for <*>", rendered)
        self.assertIn("count: 1", rendered)
        self.assertIn("threshold: 3", rendered)
        self.assertIn("Rare template", rendered)
        self.assertIn("next steps:", rendered)

    # ── drain3 smoke test ─────────────────────────────────────────────────────

    def test_run_drain3_adds_columns(self) -> None:
        """_run_drain3 must add non-null template_id and template_str columns."""
        rows = [
            {"ts": _BASE_TS + i, "host": "192.0.2.1",
             "raw": f"line {i}", "message": msg}
            for i, msg in enumerate([
                "sshd[*]: session opened for user admin",
                "sshd[*]: session opened for user root",
                "sshd[*]: session closed for user admin",
                "kernel: device eth0 entered promiscuous mode",
                "kernel: device eth1 entered promiscuous mode",
            ])
        ]
        df = _make_df(rows)
        result = _run_drain3(df, sim_thresh=0.5, depth=4, parametrize_numeric=True)

        self.assertIn("template_id", result.columns)
        self.assertIn("template_str", result.columns)
        self.assertFalse(result["template_id"].isna().any(), "template_id should have no nulls")
        self.assertFalse(result["template_str"].isna().any(), "template_str should have no nulls")
        self.assertEqual(len(result), len(df))

    def test_drain3_bar_honors_narration_gate(self) -> None:
        """The drain3 miner bar is detector-owned but routes through the runner's
        global narration gate: -q (gate off) silences it WITHOUT this detector
        reading a quiet field, while gate-on + a TTY still narrates. Guards the
        wiring that lets -q reach the bar (the render-blind rail stays intact)."""
        from sigwood.common import display as display_mod

        df = _make_df(
            [{"ts": _BASE_TS + i, "host": "192.0.2.1", "raw": f"l{i}",
              "message": f"sshd[*]: event {i}"} for i in range(20)]
        )

        class _FakeTTY(io.StringIO):
            def isatty(self) -> bool:  # tqdm writes here; force the TTY arm
                return True

        saved = display_mod._NARRATION_ENABLED
        try:
            for enabled in (True, False):
                display_mod.set_narration_enabled(enabled)
                cap = _FakeTTY()
                with patch.object(sys, "stderr", cap):
                    _run_drain3(df, sim_thresh=0.5, depth=4, parametrize_numeric=True)
                emitted = "mining templates" in cap.getvalue()
                self.assertEqual(
                    emitted, enabled,
                    f"narration enabled={enabled}: bar emitted={emitted} (expected {enabled})",
                )
        finally:
            display_mod._NARRATION_ENABLED = saved


# ── Fidelity-aware v1: dns-shape REQUIRES_ONE_OF_OPTIONAL contract ──────────


def _zeek_syslog_row(i: int, ts_offset: float = 0.0) -> dict:
    """A Zeek-frame syslog row with facility/severity carried.

    Detector is source-blind - facility/severity must ride along without ever
    being read. The frame carries the minimal-5 plus the extended pair.
    """
    return {
        "ts":       _BASE_TS + ts_offset + i * 60.0,
        "host":     "192.0.2.1",
        "program":  "sshd",
        "raw":      f"Jun 11 12:{i:02d}:00 host1 sshd[1234]: Accepted publickey for user",
        "message":  "sshd[*]: Accepted publickey for user",
        "facility": "DAEMON",
        "severity": "INFO",
    }


def _ctx_zeek_only(df: pd.DataFrame, cfg: dict | None = None) -> DetectorContext:
    """Context with frame keyed at the Zeek-syslog pattern key only."""
    return DetectorContext(
        logs={"syslog*.log*": df},
        config=cfg or {},
        allowlist=None,
        data_window=_WINDOW,
    )


def _ctx_both(
    flat_df: pd.DataFrame, zeek_df: pd.DataFrame, cfg: dict | None = None,
) -> DetectorContext:
    """Context with BOTH source keys populated (concat path)."""
    return DetectorContext(
        logs={"*.log*": flat_df, "syslog*.log*": zeek_df},
        config=cfg or {},
        allowlist=None,
        data_window=_WINDOW,
    )


def test_detector_module_exposes_dns_shape_optional_contract() -> None:
    """REQUIRED_LOGS empty; OPTIONAL_LOGS lists all feeds; ONE-OF gate on."""
    import sigwood.detectors.syslog as mod
    assert mod.REQUIRED_LOGS == []
    assert {(o["source"], o["pattern"]) for o in mod.OPTIONAL_LOGS} == {
        ("syslog_dir", "*.log*"),
        ("journal",    "*.log*"),
        ("zeek_dir",   "syslog*.log*"),
    }
    assert mod.REQUIRES_ONE_OF_OPTIONAL is True
    # The reason carries NO detector name - both render surfaces prefix it.
    assert mod.REQUIRES_ONE_OF_OPTIONAL_REASON == (
        "no syslog source found (need a readable system journal, syslog files, "
        "or Zeek syslog.log)"
    )
    assert not mod.REQUIRES_ONE_OF_OPTIONAL_REASON.startswith("syslog")  # no double-name


def test_run_returns_empty_when_no_source_frames_present() -> None:
    """Both pattern keys absent → empty findings. REQUIRES_ONE_OF_OPTIONAL
    is enforced upstream by the runner; the detector itself degrades cleanly
    when called with no frames."""
    ctx = DetectorContext(
        logs={}, config={}, allowlist=None,
        data_window=_WINDOW,
    )
    assert run(ctx) == []


def test_run_zeek_only_context_produces_findings_and_is_source_blind() -> None:
    """Zeek frame (with facility/severity) drives detection; detector never
    touches the extended columns. Source-blindness rail: the row tuples used
    in the detector body have NO facility/severity attribute access."""
    rows = [_zeek_syslog_row(i) for i in range(20)]
    rows.append({
        "ts":       _BASE_TS + 30 * 60.0,
        "host":     "192.0.2.1",
        "program":  "kernel",
        "raw":      "Jun 11 12:30:00 host1 kernel: rare placeholder event",
        "message":  "kernel: rare placeholder event",
        "facility": "KERN",
        "severity": "ERR",
    })
    df = pd.DataFrame(rows)
    # Inject a stable template-id split: 20 commons + 1 rare.
    template_ids  = [1] * 20 + [2]
    template_strs = ["common"] * 20 + ["rare"]

    with patch(
        "sigwood.detectors.syslog._run_drain3",
        _patched_drain3(template_ids, template_strs),
    ):
        findings = run(_ctx_zeek_only(df))

    # One rare → at least one finding (drain3 patched to a known split).
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_run_concats_both_frames_in_order(monkeypatch) -> None:
    """When both pattern keys are populated, run() concats flat + Zeek before
    drain3 - the precedent is detectors/dns.py:_run_zeek_path-and-pihole-enrichment.
    Asserts the concatenated frame's row count matches sum-of-inputs, proving
    no de-dup / drop on union."""
    flat_rows = [_common_row(i) for i in range(5)]
    zeek_rows = [_zeek_syslog_row(i, ts_offset=10_000.0) for i in range(3)]
    flat_df = pd.DataFrame(flat_rows)
    zeek_df = pd.DataFrame(zeek_rows)

    seen_lengths: list[int] = []

    def _capture_drain3(df, *args, **kwargs):
        seen_lengths.append(len(df))
        df = df.copy()
        df["template_id"]  = [1] * len(df)
        df["template_str"] = ["common"] * len(df)
        return df

    monkeypatch.setattr(
        "sigwood.detectors.syslog._run_drain3", _capture_drain3
    )
    run(_ctx_both(flat_df, zeek_df))
    assert seen_lengths == [len(flat_rows) + len(zeek_rows)]


def test_run_source_blind_no_facility_severity_required(monkeypatch) -> None:
    """A frame missing facility/severity entirely still runs (flat-shape on
    the Zeek key). Verifies the detector body references no extended column."""
    rows = [_common_row(i) for i in range(20)]
    rows.append({
        "ts":      _BASE_TS + 30 * 60.0,
        "host":    "192.0.2.1",
        "program": "kernel",
        "raw":     "Jun 11 12:30:00 host1 kernel: rare placeholder",
        "message": "kernel: rare placeholder",
    })
    df = pd.DataFrame(rows)
    template_ids  = [1] * 20 + [2]
    template_strs = ["common"] * 20 + ["rare"]
    monkeypatch.setattr(
        "sigwood.detectors.syslog._run_drain3",
        _patched_drain3(template_ids, template_strs),
    )
    findings = run(_ctx_zeek_only(df))
    assert findings, "detector must run on a minimal-5 frame keyed at the Zeek pattern"


def test_flat_and_zeek_reboot_rows_have_identical_detector_semantics() -> None:
    row = {
        "ts": _BASE_TS,
        "host": "host.example",
        "program": "systemd-logind",
        "raw": "systemd-logind[1]: System is rebooting.",
        "message": "systemd-logind: System is rebooting.",
    }
    frame = pd.DataFrame([row])
    contexts = (_ctx(frame), _ctx_zeek_only(frame))
    observed: list[tuple[Severity, str, str]] = []
    for context in contexts:
        with patch(
            "sigwood.detectors.syslog._run_drain3",
            _patched_drain3([1], ["reboot"]),
        ):
            findings = run(context)
        assert len(findings) == 1
        observed.append(
            (findings[0].severity, findings[0].evidence["tier"], findings[0].title)
        )
    assert observed == [
        (Severity.INFO, "reboot", "host.example"),
        (Severity.INFO, "reboot", "host.example"),
    ]


def test_journal_program_identity_reaches_drain3_when_raw_messages_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows: list[dict] = []
    for program in ("sshd", "kernel"):
        parsed = parse_journal_record(json.dumps({
            "__REALTIME_TIMESTAMP": "1760000000000000",
            "MESSAGE": "same payload",
            "_HOSTNAME": "host.example",
            "SYSLOG_IDENTIFIER": program,
        }))
        assert isinstance(parsed, dict)
        rows.append(parsed)

    observed: list[str] = []

    def capture_messages(df, *args, **kwargs):
        del args, kwargs
        observed.extend(df["message"].tolist())
        result = df.copy()
        result["template_id"] = [1, 2]
        result["template_str"] = ["sshd payload", "kernel payload"]
        return result

    monkeypatch.setattr(
        "sigwood.detectors.syslog._run_drain3", capture_messages
    )
    run(_ctx(pd.DataFrame(rows)))
    assert observed == ["sshd: same payload", "kernel: same payload"]


if __name__ == "__main__":
    unittest.main()


def test_unlabeled_burst_description_never_claims_boot() -> None:
    """An unlabeled burst must not be narrated as a boot the detector never
    observed; the reboot wording appears only after _reconcile labels it."""
    rows = [_rare_row(_BASE_TS + i, "h", f"r{i}", program="cron", template_id=i)
            for i in range(3)]
    burst_pairs, remainder = _collapse_bursts(
        _rare_df(rows),
        gap_seconds=60, min_size=3, now=_NOW, data_window=_WINDOW,
    )
    assert remainder.empty
    assert len(burst_pairs) == 1
    burst = burst_pairs[0][1]
    assert "boot" not in burst.description.lower()

    evt = _BootEvent("h", _BASE_TS + 1, _BASE_TS + 1, 1)
    _reconcile([evt], burst_pairs, gap_seconds=60, now=_NOW, data_window=_WINDOW)
    assert burst.evidence["label"] == "rebooted"
    assert "reboot" in burst.description
