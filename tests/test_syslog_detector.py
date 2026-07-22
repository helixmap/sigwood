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
    DEFAULT_CONFIG,
    DETECTOR_NAME,
    _FRAGMENT_LIMIT,
    _FRAGMENT_TEMPLATE_SCAN_LIMIT,
    LINE_TRIM_LIMIT,
    PRIVILEGED_PROGRAMS,
    STATUS,
    REBOOT_CLUSTER_SECONDS,
    ADMIN_SESSION_CLUSTER_SECONDS,
    UPDATE_RUN_CLUSTER_SECONDS,
    TRANSACTION_LEAD_TOLERANCE_SECONDS,
    TRANSACTION_TAIL_TOLERANCE_SECONDS,
    _BootEvent,
    _TransactionEvent,
    _collapse_bursts,
    _collapse_families,
    _contains_opaque_hex,
    _decorate_burst_first_seen,
    _detect_boot_events,
    _detect_transaction_events,
    _distill_member_fragments,
    _gap_cluster,
    _is_ip_token,
    _is_decimal_composite,
    _keep_fragment_token,
    _normalize_identity_columns,
    _reboot_finding,
    _reconcile,
    _reconcile_transactions,
    _run_drain3,
    _truncate_fragment,
    run,
)
from sigwood.parsers.syslog import REBOOT_SIGNALS_RE, is_reboot_signal, strip_program
from sigwood.parsers.journal import parse_record as parse_journal_record
from sigwood.outputs._render_model import Section as _Section


def _flat_section(findings: list[Finding]) -> list[_Section]:
    """Wrap findings into the single-section shape per the renderer contract."""
    return [_Section(None, list(findings), len(findings))]

_NOW    = datetime(2026, 5, 30, tzinfo=timezone.utc)
_WINDOW = (_NOW, _NOW)

# Fixed unix epoch used across fixtures (2026-05-30 00:00:00 UTC)
_BASE_TS = 1_748_563_200.0
_Member = namedtuple("_Member", "template_id message")


def _case_two_fragment_reference(rows) -> list[str]:
    """Reference the interleaved scan semantics used by fallback fragments."""
    seen_templates: set[object] = set()
    seen_fragments: set[str] = set()
    fragments: list[str] = []
    for row in rows:
        template_id = getattr(row, "template_id", None)
        message = getattr(row, "message", None)
        if template_id is None or message is None:
            continue
        if pd.isna(template_id) or pd.isna(message):
            continue
        if template_id in seen_templates:
            continue
        if len(seen_templates) >= _FRAGMENT_TEMPLATE_SCAN_LIMIT:
            break
        seen_templates.add(template_id)
        kept = [
            token
            for token in strip_program(str(message)).split()
            if _keep_fragment_token(token)
        ]
        distilled = " ".join(kept).strip()
        if not distilled:
            continue
        rendered = _truncate_fragment(distilled)
        if rendered in seen_fragments:
            continue
        seen_fragments.add(rendered)
        fragments.append(rendered)
        if len(fragments) >= _FRAGMENT_LIMIT:
            break
    return fragments


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


def _family_fold(
    df: pd.DataFrame,
    *,
    min_size=2,
    threshold=1,
    severity: Severity = Severity.LOW,
    privileged: bool = False,
    program_totals: dict | None = None,
    line_trim_limit: int = LINE_TRIM_LIMIT,
):
    """Run the family seam over a hand-built isolated remainder."""
    freq = {
        int(template_id): int(count)
        for template_id, count in df["template_id"].value_counts().items()
    }
    if program_totals is None:
        identities = df.copy()
        for column in ("host", "program"):
            if column not in identities:
                identities[column] = "unknown"
            else:
                identities[column] = identities[column].fillna("unknown")
        program_totals = {
            key: int(len(group))
            for key, group in identities.groupby(["host", "program"], sort=False)
        }
    return _collapse_families(
        df, freq, threshold, min_size=min_size,
        now=_NOW, data_window=_WINDOW,
        severity=severity, privileged=privileged, program_totals=program_totals,
        line_trim_limit=line_trim_limit,
    )


def _run_with(rows: list[dict], ids: list[int], strs: list[str], cfg: dict | None = None):
    """Run the full detector with drain3 patched to a known template split."""
    df = pd.DataFrame(rows)
    with patch("sigwood.detectors.syslog._run_drain3", _patched_drain3(ids, strs)):
        return run(_ctx(df, cfg or {"max_count": 1, "rarity_pct": 10}))


def _stored_needle(
    ts: float,
    host: str,
    title: str,
    *,
    program: str = "cron",
    privileged: bool = False,
) -> tuple[float, Finding]:
    first_seen = (
        None if pd.isna(ts)
        else datetime.fromtimestamp(ts, timezone.utc).isoformat()
    )
    evidence = {
        "host": host,
        "program": program,
        "first_seen": first_seen,
        "self_stamped": False,
    }
    if privileged:
        evidence["privileged"] = True
    return (
        ts,
        Finding(
            detector="syslog",
            severity=Severity.MEDIUM if privileged else Severity.LOW,
            title=title,
            description="Rare template.",
            evidence=evidence,
            next_steps=[],
            ts_generated=_NOW,
            data_window=_WINDOW,
        ),
    )


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

    def test_privileged_roster_exact_and_default_is_fresh_copy(self) -> None:
        self.assertEqual(len(PRIVILEGED_PROGRAMS), 31)
        self.assertEqual(PRIVILEGED_PROGRAMS, (
            "sshd", "sshd-session", "sshd-auth", "login", "sulogin",
            "sudo", "su", "runuser", "doas", "pkexec", "polkitd",
            "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
            "passwd", "chpasswd", "chage", "gpasswd", "newusers", "chgpasswd",
            "groupmems", "chsh", "newgrp", "sg", "auditd", "audisp-syslog",
            "audispd", "systemd-coredump",
        ))
        self.assertEqual(DEFAULT_CONFIG["privileged_programs"], list(PRIVILEGED_PROGRAMS))
        self.assertIsNot(DEFAULT_CONFIG["privileged_programs"], PRIVILEGED_PROGRAMS)

    # ── Capsule member fragments ──────────────────────────────────────────────

    def test_overflow_case_backfills_after_rendered_fragment_collisions(self) -> None:
        shared = "q" * 199
        rows = [
            _Member(1, f"prog: {shared}AX"),
            _Member(2, f"prog: {shared}BY"),
            _Member(3, "prog: deadbeefcafe"),
            _Member(4, "sshd[*]: accepted from 192.0.2.9"),
            _Member(5, "kernel: oops"),
            _Member(6, "postfix: connect"),
            _Member(7, "prog: must-not-enter-fallback"),
        ]
        self.assertEqual(
            _distill_member_fragments(rows),
            [shared + "…", "accepted from 192.0.2.9", "oops"],
        )
        self.assertNotIn("must-not-enter-fallback", " ".join(_distill_member_fragments(rows)))

    def test_overflow_case_preserves_interleaved_fragment_output(self) -> None:
        rows = [
            _Member(i, f"prog: fragment-{i}") for i in range(1, 8)
        ]
        expected = _case_two_fragment_reference(rows)
        self.assertEqual(expected, ["fragment-1", "fragment-2", "fragment-3"])
        self.assertEqual(_distill_member_fragments(rows), expected)
        self.assertFalse(_distill_member_fragments(rows)[0].startswith("tokens: "))

    def test_fragment_uses_first_usable_row_per_template(self) -> None:
        rows = [
            _Member(1, None),
            _Member(1, "prog: first usable"),
            _Member(1, "prog: later duplicate id"),
            _Member(float("nan"), "prog: no id"),
            _Member(2, "prog: second template"),
        ]
        self.assertEqual(
            _distill_member_fragments(rows),
            ["tokens: first usable second template"],
        )

    def test_complete_tokens_line_keeps_order_and_first_verbatim_form(self) -> None:
        rows = [
            _Member(1, "prog: for /net/backups (/net/backups) From from"),
            _Member(2, "prog: next from"),
        ]
        self.assertEqual(
            _distill_member_fragments(rows),
            ["tokens: for /net/backups From from next"],
        )

    def test_ip_exemption_accepts_only_approved_compounds(self) -> None:
        for token in (
            "192.0.2.9",
            "(2001:db8::1),",
            "fe80::1%eth0",
            "192.0.2.9:443",
            "[2001:db8::1]:8443",
        ):
            self.assertTrue(_is_ip_token(token), token)
        for token in (
            "192.0.2.9:https",
            "[2001:db8::1]:https",
            "2001:db8::1:http",
        ):
            self.assertFalse(_is_ip_token(token), token)

    def test_opaque_hex_rule_keeps_magnitudes_and_drops_identifier_runs(self) -> None:
        kept = (
            "22", "1234", "pid=1234", "SRC=192.0.2.9", "104857600",
            "1699999999", "192.0.2.9", "2001:db8::1",
            "00:1a:2b:3c:4d:5e", "x_12345678",
        )
        self.assertTrue(all(_keep_fragment_token(token) for token in kept))
        for token in ("deadbeefcafe", "a1b2c3d4e5f6", "session=9f8e7d6c5b4a"):
            self.assertTrue(_contains_opaque_hex(token), token)
            self.assertFalse(_keep_fragment_token(token), token)
        for token in ("104857600", "x_12345678", "00:1a:2b:3c:4d:5e"):
            self.assertFalse(_contains_opaque_hex(token), token)

    def test_decimal_composite_rule_matches_ratified_boundary(self) -> None:
        dropped = ("audit(1784390923.524:417815):", "1784390923.524")
        kept = (
            "104857600", "22", "1234", "0", "192.0.2.9:1007",
            "SRC=192.0.2.9", "2026-07-18", "03:22:01.564",
            "1.11.0-1_all", "aa:bb:cc:dd:ee:ff",
        )
        self.assertTrue(all(_is_decimal_composite(token) for token in dropped))
        self.assertTrue(all(not _is_decimal_composite(token) for token in kept))
        self.assertTrue(all(not _keep_fragment_token(token) for token in dropped))
        self.assertTrue(all(_keep_fragment_token(token) for token in kept))

    def test_ip_exemption_precedes_decimal_composite_drop(self) -> None:
        token = "192.0.2.9:1784390923"
        self.assertTrue(_is_decimal_composite(token))
        self.assertTrue(_is_ip_token(token))
        self.assertTrue(_keep_fragment_token(token))

    def test_tokens_line_keeps_zero_alnum_glue_and_excludes_empty_results(self) -> None:
        rows = [
            _Member(1, "prog: deadbeef -> cafebabecafe"),
            _Member(2, "prog: deadbeefcafe"),
        ]
        self.assertEqual(_distill_member_fragments(rows), ["tokens: ->"])
        self.assertEqual(
            _distill_member_fragments([_Member(1, "prog: deadbeefcafe")]),
            [],
        )

    def test_fragment_length_budget_prefers_boundary_then_hard_cuts(self) -> None:
        boundary = "a " + ("q" * 198) + " tail"
        self.assertEqual(_truncate_fragment(boundary), "a…")
        overlong = "q" * 201
        self.assertEqual(_truncate_fragment(overlong), ("q" * 199) + "…")
        self.assertEqual(len(_truncate_fragment(overlong)), 200)

    def test_complete_tokens_line_uses_full_prefixed_length_discriminator(self) -> None:
        fits = _distill_member_fragments([_Member(1, "prog: " + ("q" * 192))])
        self.assertEqual(fits, ["tokens: " + ("q" * 192)])
        self.assertEqual(len(fits[0]), 200)

        over = _distill_member_fragments([_Member(1, "prog: " + ("q" * 193))])
        self.assertEqual(over, [("q" * 193)])
        self.assertFalse(over[0].startswith("tokens: "))

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

    def test_run_returns_low_sieve_finding_for_anomalous_row(self) -> None:
        """One unprivileged rare template among common rows → one LOW finding."""
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
        self.assertEqual(findings[0].severity, Severity.LOW)
        self.assertNotIn("privileged", findings[0].evidence)

    def test_line_trim_limit_controls_needle_title_only(self) -> None:
        raw = (
            "<30>May 30 13:00:00 192.0.2.2 kernel: "
            + ("needle-content-" * 20)
        )
        rows = [_common_row(i) for i in range(50)] + [{
            "ts": _BASE_TS + 3600.0,
            "host": "192.0.2.2",
            "raw": raw,
            "message": "kernel: " + ("needle-content-" * 20),
        }]
        ids = [1] * 50 + [2]
        templates = ["sshd[*]: Accepted publickey for admin"] * 50 + [
            "kernel: <*>"
        ]

        findings = _run_with(
            rows,
            ids,
            templates,
            {"max_count": 1, "rarity_pct": 10, "line_trim_limit": 50},
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, raw[:50])

    def test_absent_line_trim_limit_keeps_200_character_needle_default(self) -> None:
        raw = "<30>May 30 13:00:00 192.0.2.2 kernel: " + ("q" * 240)
        rows = [_common_row(i) for i in range(50)] + [{
            "ts": _BASE_TS + 3600.0,
            "host": "192.0.2.2",
            "raw": raw,
            "message": "kernel: " + ("q" * 240),
        }]
        ids = [1] * 50 + [2]
        templates = ["sshd[*]: Accepted publickey for admin"] * 50 + [
            "kernel: <*>"
        ]

        findings = _run_with(
            rows,
            ids,
            templates,
            {"max_count": 1, "rarity_pct": 10},
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, raw[:200])
        self.assertEqual(len(findings[0].title), 200)

    def test_line_trim_limit_does_not_cap_family_meat(self) -> None:
        rows = _rare_df([
            _rare_row(
                _BASE_TS,
                "192.0.2.2",
                "raw-a",
                program="kernel",
                template_id=1,
                message="kernel: " + ("q" * 70),
            ),
            _rare_row(
                _BASE_TS + 120.0,
                "192.0.2.2",
                "raw-b",
                program="kernel",
                template_id=2,
                message="kernel: " + ("r" * 70),
            ),
        ])

        pairs = _family_fold(rows, line_trim_limit=10)

        self.assertEqual(len(pairs), 1)
        fragments = pairs[0][1].evidence["member_fragments"]
        self.assertEqual(fragments, ["tokens: " + ("q" * 70) + " " + ("r" * 70)])
        self.assertTrue(all(len(fragment) > 10 for fragment in fragments))

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

    def test_collapse_missing_fragment_columns_is_contained(self) -> None:
        df = pd.DataFrame(
            [
                {"ts": _BASE_TS + i, "host": "h", "raw": f"r{i}", "program": "p"}
                for i in range(3)
            ]
        )
        pairs, remainder = _collapse_bursts(
            df, gap_seconds=60, min_size=3, now=_NOW, data_window=_WINDOW,
        )
        self.assertTrue(remainder.empty)
        self.assertEqual(pairs[0][1].evidence["member_fragments"], [])

    def test_burst_repeated_template_has_one_fragment(self) -> None:
        rows = [
            _rare_row(
                _BASE_TS + i, "h", f"raw-{i}", template_id=7,
                message="kernel: repeated message",
            )
            for i in range(3)
        ]
        burst = _collapse(rows)[0]
        self.assertEqual(
            burst.evidence["member_fragments"], ["tokens: repeated message"]
        )

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
        self.assertEqual(family.severity, Severity.LOW)
        self.assertEqual(family.title, "host-a")
        self.assertEqual(family.evidence, {
            "tier": "family",
            "host": "host-a",
            "program": "sshd",
            "line_count": 2,
            "program_total": 2,
            "start_ts": _BASE_TS,
            "end_ts": _BASE_TS + 120,
            "first_seen": datetime.fromtimestamp(_BASE_TS, timezone.utc).isoformat(),
            "span_seconds": 120.0,
            "sample_raw": ["a0", "a1"],
            "member_fragments": ["tokens: m"],
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

    def test_member_fragments_present_on_capsules_absent_elsewhere(self) -> None:
        family_rows = [
            _rare_row(_BASE_TS + i * 120, "h", f"f-{i}", template_id=i,
                      message="prog: deadbeefcafe")
            for i in range(2)
        ]
        family = _family_fold(_rare_df(family_rows))[0][1]
        self.assertEqual(family.evidence["member_fragments"], [])

        burst_rows = [
            _rare_row(_BASE_TS + i, "b", f"b-{i}", template_id=i,
                      message=f"prog: burst fragment {i}")
            for i in range(3)
        ]
        burst = _collapse(burst_rows)[0]
        self.assertEqual(
            burst.evidence["member_fragments"],
            ["tokens: burst fragment 0 1 2"],
        )

        needle = _family_fold(_rare_df([
            _rare_row(_BASE_TS, "n", "needle", template_id=9),
        ]))[0][1]
        self.assertNotIn("member_fragments", needle.evidence)

        reboot = _reboot_finding(
            _BootEvent("r", _BASE_TS, _BASE_TS, 1), _NOW, _WINDOW,
        )[1]
        self.assertNotIn("member_fragments", reboot.evidence)

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
        self.assertIsNone(family.evidence["first_seen"])
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

    def test_family_zero_epoch_first_seen_is_not_none(self) -> None:
        rows = [
            _rare_row(0.0, "h", "zero", program="p", template_id=1),
            _rare_row(1.0, "h", "one", program="p", template_id=2),
        ]
        _, family = _family_fold(_rare_df(rows))[0]
        self.assertEqual(family.evidence["first_seen"], "1970-01-01T00:00:00+00:00")

    def test_family_of_one_is_low_needle_with_program_total(self) -> None:
        row = _rare_row(_BASE_TS, "h", "raw-one", program="sshd", template_id=1)
        finding = _family_fold(_rare_df([row]))[0][1]
        self.assertEqual(finding.severity, Severity.LOW)
        self.assertEqual(finding.evidence["program"], "sshd")
        self.assertEqual(finding.evidence["program_total"], 1)
        self.assertNotIn("privileged", finding.evidence)

    def test_needles_pin_stamp_evidence_on_both_membership_channels(self) -> None:
        flat = _rare_row(
            _BASE_TS, "flat-host",
            "May 30 12:00:00 flat-host cron: flat payload",
            program="cron", template_id=7, template_str="cron: flat payload",
        )
        _, sieve = _family_fold(_rare_df([flat]))[0]
        self.assertEqual(sieve.severity, Severity.LOW)
        self.assertEqual(sieve.evidence, {
            "host": "flat-host",
            "program": "cron",
            "program_total": 1,
            "template_id": 7,
            "template_str": "cron: flat payload",
            "count": 1,
            "threshold": 1,
            "first_seen": datetime.fromtimestamp(_BASE_TS, timezone.utc).isoformat(),
            "self_stamped": True,
        })

        journal = _rare_row(
            _BASE_TS + 1, "journal-host", "bare journal payload",
            program="sudo", template_id=8, template_str="sudo: bare journal payload",
        )
        _, member = _family_fold(
            _rare_df([journal]), severity=Severity.MEDIUM, privileged=True,
        )[0]
        self.assertEqual(member.severity, Severity.MEDIUM)
        self.assertEqual(member.evidence, {
            "host": "journal-host",
            "program": "sudo",
            "program_total": 1,
            "template_id": 8,
            "template_str": "sudo: bare journal payload",
            "count": 1,
            "threshold": 1,
            "first_seen": datetime.fromtimestamp(
                _BASE_TS + 1, timezone.utc
            ).isoformat(),
            "self_stamped": False,
            "privileged": True,
        })

    def test_nan_timestamp_needle_keeps_content_stamp_fact(self) -> None:
        row = _rare_row(
            float("nan"), "h", "bare journal payload",
            template_id=9, template_str="bare journal payload",
        )
        sort_ts, finding = _family_fold(_rare_df([row]))[0]
        self.assertEqual(sort_ts, float("inf"))
        self.assertIsNone(finding.evidence["first_seen"])
        self.assertIs(finding.evidence["self_stamped"], False)

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

    def test_two_channel_pipeline_conserves_every_unique_member_once(self) -> None:
        rows = (
            [_rare_row(_BASE_TS + i, "burst", f"sieve-burst-{i}",
                       program="cron", template_id=10 + i) for i in range(3)]
            + [_rare_row(_BASE_TS + i * 120, "sfam", f"sieve-family-{i}",
                         program="kernel", template_id=20 + i) for i in range(2)]
            + [_rare_row(_BASE_TS + 500, "sneedle", "sieve-needle",
                         program="cron", template_id=30)]
            + [_rare_row(_BASE_TS + i * 120, "mfam", f"member-family-{i}",
                         program="useradd", template_id=40 + i) for i in range(2)]
            + [_rare_row(_BASE_TS + 500, "mneedle", "member-needle",
                         program="sshd", template_id=50)]
            + [_rare_row(float("nan"), "mnan", "member-nan",
                         program="sudo", template_id=60)]
        )
        frame = _rare_df(rows)
        frame.index = [7] * len(frame)  # duplicate source indexes cannot expand complements
        work = frame.copy()
        mask = work["program"].isin(set(PRIVILEGED_PROGRAMS) - {"unknown"})
        members, sieve = work.loc[mask].copy(), work.loc[~mask].copy()
        identities = _normalize_identity_columns(work)
        totals = {
            key: int(len(group))
            for key, group in identities.groupby(["host", "program"], sort=False)
        }
        freq = {int(t): 1 for t in work["template_id"]}
        bursts, sieve_remainder = _collapse_bursts(
            sieve, gap_seconds=60, min_size=3, now=_NOW, data_window=_WINDOW,
        )
        sieve_pairs = _collapse_families(
            sieve_remainder, freq, 1, min_size=2, now=_NOW, data_window=_WINDOW,
            severity=Severity.LOW, privileged=False, program_totals=totals,
        )
        member_pairs = _collapse_families(
            members, freq, 1, min_size=2, now=_NOW, data_window=_WINDOW,
            severity=Severity.MEDIUM, privileged=True, program_totals=totals,
        )

        represented: list[str] = []
        findings = [f for _, f in [*bursts, *sieve_pairs, *member_pairs]]
        for finding in findings:
            if finding.evidence.get("tier") in ("burst", "family"):
                represented.extend(finding.evidence["sample_raw"])
            else:
                represented.append(finding.title)
        self.assertEqual(Counter(represented), Counter(str(raw) for raw in frame["raw"]))
        self.assertFalse(any(f.severity == Severity.HIGH for f in findings))
        self.assertTrue(all(
            f.evidence.get("privileged") is True
            for _, f in member_pairs
        ))
        self.assertTrue(all("privileged" not in f.evidence for _, f in sieve_pairs))

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
        self.assertEqual(families[0].severity, Severity.MEDIUM)
        self.assertIs(families[0].evidence["privileged"], True)
        self.assertEqual(families[0].evidence["line_count"], 2)
        self.assertEqual(
            families[0].evidence["sample_raw"],
            ["sshd: privileged login sentinel", "sshd: persistence sentinel"],
        )
        self.assertFalse([f for f in result if f.evidence.get("tier") is None])

    def test_roster_membership_is_exact_case_sensitive_and_never_unknown(self) -> None:
        common = [_common_row(i) for i in range(20)]
        programs = ["sshd", "SSHD", "sshd/session", "unknown", None]
        rare = [
            {
                "ts": _BASE_TS + 100_000 + i * 120,
                "host": f"host-{i}",
                "program": program,
                "raw": f"sentinel-{i}",
                "message": f"sentinel-{i}",
            }
            for i, program in enumerate(programs)
        ]
        ids = [1] * len(common) + list(range(2, 2 + len(rare)))
        strs = ["common"] * len(common) + [f"rare-{i}" for i in range(len(rare))]
        findings = _run_with(
            common + rare, ids, strs,
            {"max_count": 1, "rarity_pct": 10,
             "privileged_programs": ["sshd", "unknown"]},
        )
        by_title = {finding.title: finding for finding in findings}
        self.assertEqual(by_title["sentinel-0"].severity, Severity.MEDIUM)
        self.assertIs(by_title["sentinel-0"].evidence["privileged"], True)
        for i in range(1, 5):
            self.assertEqual(by_title[f"sentinel-{i}"].severity, Severity.LOW)
            self.assertNotIn("privileged", by_title[f"sentinel-{i}"].evidence)

    def test_run_hands_raw_sieve_frame_to_unchanged_burst_pass(self) -> None:
        common = [_common_row(i) for i in range(20)]
        rare = [{"ts": _BASE_TS + 100_000, "host": None, "program": None,
                 "raw": "raw-sieve", "message": "raw-sieve"}]
        captured: dict[str, pd.DataFrame] = {}

        def _capture(frame: pd.DataFrame, **kwargs):
            captured["frame"] = frame.copy()
            return _collapse_bursts(frame, **kwargs)

        with (
            patch(
                "sigwood.detectors.syslog._run_drain3",
                _patched_drain3([1] * 20 + [2], ["common"] * 20 + ["rare"]),
            ),
            patch("sigwood.detectors.syslog._collapse_bursts", side_effect=_capture),
        ):
            run(_ctx(pd.DataFrame(common + rare), {"max_count": 1, "rarity_pct": 10}))

        sieve = captured["frame"]
        self.assertEqual(list(sieve.index), [20])
        self.assertTrue(pd.isna(sieve.iloc[0]["host"]))
        self.assertTrue(pd.isna(sieve.iloc[0]["program"]))

    def test_member_never_bursts_while_sieve_siblings_do(self) -> None:
        common = [_common_row(i) for i in range(20)]
        rare = [
            {"ts": _BASE_TS + 100_000, "host": "h", "program": "useradd",
             "raw": "member", "message": "member"},
            *[
                {"ts": _BASE_TS + 100_001 + i, "host": "h", "program": "cron",
                 "raw": f"sieve-{i}", "message": f"sieve-{i}"}
                for i in range(3)
            ],
        ]
        ids = [1] * len(common) + [2, 3, 4, 5]
        strs = ["common"] * len(common) + ["member", "s0", "s1", "s2"]
        findings = _run_with(common + rare, ids, strs)
        member = next(f for f in findings if f.title == "member")
        burst = next(f for f in findings if f.evidence.get("tier") == "burst")
        self.assertEqual(member.severity, Severity.MEDIUM)
        self.assertIs(member.evidence["privileged"], True)
        self.assertEqual(burst.severity, Severity.INFO)
        self.assertEqual(burst.evidence["sample_raw"], ["sieve-0", "sieve-1", "sieve-2"])

    def test_member_nan_timestamp_survives_as_medium(self) -> None:
        common = [_common_row(i) for i in range(20)]
        rare = [{"ts": float("nan"), "host": "h", "program": "sudo",
                 "raw": "nan-member", "message": "nan-member"}]
        finding = _run_with(common + rare, [1] * 20 + [2], ["common"] * 20 + ["rare"])[0]
        self.assertEqual(finding.title, "nan-member")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertIs(finding.evidence["privileged"], True)

    def test_program_total_counts_full_loaded_host_program_population(self) -> None:
        rows = [
            {"ts": _BASE_TS + i, "host": "h", "program": "useradd",
             "raw": f"common-{i}", "message": "common"}
            for i in range(20)
        ]
        rows.append({"ts": _BASE_TS + 100, "host": "h", "program": "useradd",
                     "raw": "rare", "message": "rare"})
        finding = _run_with(rows, [1] * 20 + [2], ["common"] * 20 + ["rare"])[0]
        self.assertEqual(finding.evidence["program_total"], 21)
        self.assertEqual(finding.evidence["count"], 1)

    def test_burst_first_seen_decorator_preserves_identity_and_reconcile_claim(self) -> None:
        rows = [_rare_row(_BASE_TS + i, "h", f"r{i}", program="cron", template_id=i)
                for i in range(3)]
        burst_pairs, remainder = _collapse_bursts(
            _rare_df(rows), gap_seconds=60, min_size=3, now=_NOW, data_window=_WINDOW,
        )
        self.assertTrue(remainder.empty)
        stored = burst_pairs[0][1]
        stored_id = id(stored)
        _decorate_burst_first_seen(burst_pairs)
        self.assertEqual(id(burst_pairs[0][1]), stored_id)
        self.assertEqual(
            stored.evidence["first_seen"],
            datetime.fromtimestamp(_BASE_TS, timezone.utc).isoformat(),
        )
        out = _reconcile(
            [_BootEvent("h", _BASE_TS, _BASE_TS, 1)], burst_pairs,
            gap_seconds=60, now=_NOW, data_window=_WINDOW,
        )
        self.assertIs(out[0][1], stored)
        self.assertEqual(stored.evidence["label"], "rebooted")

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

    # ── Recognized transactions ───────────────────────────────────────────

    def test_admin_session_requires_open_then_close_inside_strict_gap(self) -> None:
        rows = pd.DataFrame([
            {"ts": _BASE_TS, "host": "h1",
             "message": "sshd[*]: Accepted publickey for operator"},
            {"ts": _BASE_TS + ADMIN_SESSION_CLUSTER_SECONDS - 1, "host": "h1",
             "message": "pam_unix(sshd:session): session closed for user operator"},
            {"ts": _BASE_TS, "host": "h2",
             "message": "sshd[*]: Accepted publickey for operator"},
            {"ts": _BASE_TS + ADMIN_SESSION_CLUSTER_SECONDS, "host": "h2",
             "message": "pam_unix(sshd:session): session closed for user operator"},
            {"ts": _BASE_TS, "host": "h3",
             "message": "pam_unix(sshd:session): session closed for user operator"},
            {"ts": _BASE_TS + 1, "host": "h3",
             "message": "sshd[*]: Accepted publickey for operator"},
        ])

        events = _detect_transaction_events(rows)

        self.assertEqual([(event.label, event.host) for event in events], [
            ("admin session", "h1"),
        ])
        self.assertEqual(events[0].start_ts, _BASE_TS)
        self.assertEqual(
            events[0].end_ts, _BASE_TS + ADMIN_SESSION_CLUSTER_SECONDS - 1
        )

    def test_update_run_requires_two_anchors_inside_strict_gap(self) -> None:
        rows = pd.DataFrame([
            {"ts": _BASE_TS, "host": "h1", "message": "dnf[*]: starting update"},
            {"ts": _BASE_TS + UPDATE_RUN_CLUSTER_SECONDS - 1, "host": "h1",
             "message": "rpm[*]: installed package-example"},
            {"ts": _BASE_TS, "host": "h2", "message": "dnf[*]: starting update"},
            {"ts": _BASE_TS + UPDATE_RUN_CLUSTER_SECONDS, "host": "h2",
             "message": "rpm[*]: installed package-example"},
            {"ts": _BASE_TS, "host": "h3", "message": "dnf[*]: only anchor"},
        ])

        events = _detect_transaction_events(rows)

        self.assertEqual([(event.label, event.host) for event in events], [
            ("update run", "h1"),
        ])

    def test_transaction_recognition_ignores_unknown_hosts_and_missing_time(self) -> None:
        rows = pd.DataFrame([
            {"ts": _BASE_TS, "host": "unknown",
             "message": "sshd[*]: Accepted password for operator"},
            {"ts": _BASE_TS + 1, "host": "unknown",
             "message": "pam_unix(sshd:session): session closed for user operator"},
            {"ts": float("nan"), "host": "h",
             "message": "sshd[*]: Accepted password for operator"},
            {"ts": _BASE_TS + 1, "host": "h",
             "message": "pam_unix(sshd:session): session closed for user operator"},
        ])
        self.assertEqual(_detect_transaction_events(rows), [])
        self.assertEqual(
            _detect_transaction_events(pd.DataFrame([{"host": "h"}])), []
        )

    def test_run_recognizes_transactions_before_rarity_and_conserves_members(self) -> None:
        common = [
            {**_common_row(i), "program": "cron", "message": "cron: ordinary event"}
            for i in range(50)
        ]
        anchors = [
            {"ts": _BASE_TS + 100_000 + offset, "host": "h", "program": program,
             "raw": message, "message": message}
            for offset, program, message in (
                (0, "sshd", "sshd[*]: Accepted publickey for operator"),
                (1, "sshd", "sshd[*]: Accepted publickey for operator"),
                (30, "sshd", "pam_unix(sshd:session): session closed for user operator"),
                (31, "sshd", "pam_unix(sshd:session): session closed for user operator"),
            )
        ]
        needles = [
            {"ts": _BASE_TS + 100_010, "host": "h", "program": "useradd",
             "raw": "useradd: privileged member", "message": "useradd: privileged member"},
            {"ts": _BASE_TS + 100_020, "host": "h", "program": "cron",
             "raw": "cron: sieve member", "message": "cron: sieve member"},
        ]
        ids = [1] * len(common) + [2, 2, 3, 3, 4, 5]
        templates = ["ordinary"] * len(common) + [
            "session-open", "session-open", "session-close", "session-close",
            "privileged-member", "sieve-member",
        ]

        findings = _run_with(common + anchors + needles, ids, templates)

        self.assertEqual(len(findings), 1)
        transaction = findings[0]
        self.assertEqual(transaction.evidence["tier"], "transaction")
        self.assertEqual(transaction.evidence["label"], "admin session")
        self.assertEqual(transaction.evidence["member_count"], 2)
        self.assertEqual(transaction.evidence["represented_line_count"], 2)
        self.assertEqual(transaction.severity, Severity.MEDIUM)
        self.assertIs(transaction.evidence["privileged"], True)
        members = transaction.evidence["members"]
        self.assertEqual({member["title"] for member in members}, {
            "useradd: privileged member", "cron: sieve member",
        })
        privileged = next(member for member in members if member.get("privileged"))
        self.assertEqual(privileged["severity"], "medium")

    def test_run_collapses_update_members_across_programs_as_info(self) -> None:
        common = [
            {**_common_row(i), "program": "cron", "message": "cron: ordinary event"}
            for i in range(50)
        ]
        anchors = [
            {"ts": _BASE_TS + 200_000 + offset, "host": "h", "program": program,
             "raw": message, "message": message}
            for offset, program, message in (
                (0, "dnf", "dnf[*]: starting update"),
                (1, "dnf", "dnf[*]: starting update"),
                (30, "rpm", "rpm[*]: installed package-example"),
                (31, "rpm", "rpm[*]: installed package-example"),
            )
        ]
        needles = [
            {"ts": _BASE_TS + 200_010, "host": "h", "program": "cron",
             "raw": "cron: update-side effect", "message": "cron: update-side effect"},
            {"ts": _BASE_TS + 200_020, "host": "h", "program": "kernel",
             "raw": "kernel: update-side effect", "message": "kernel: update-side effect"},
        ]
        ids = [1] * len(common) + [2, 2, 3, 3, 4, 5]
        templates = ["ordinary"] * len(common) + [
            "dnf-anchor", "dnf-anchor", "rpm-anchor", "rpm-anchor",
            "cron-side-effect", "kernel-side-effect",
        ]

        findings = _run_with(common + anchors + needles, ids, templates)

        self.assertEqual(len(findings), 1)
        transaction = findings[0]
        self.assertEqual(transaction.evidence["label"], "update run")
        self.assertEqual(transaction.evidence["member_count"], 2)
        self.assertEqual(transaction.severity, Severity.INFO)
        self.assertNotIn("privileged", transaction.evidence)
        self.assertEqual(transaction.evidence["program_mix"], [["cron", 1], ["kernel", 1]])

    def test_recognize_transactions_false_bypasses_recognition(self) -> None:
        rows = [
            {"ts": _BASE_TS + i, "host": "h", "program": "cron",
             "raw": f"rare-{i}", "message": f"rare-{i}"}
            for i in range(2)
        ]
        with patch(
            "sigwood.detectors.syslog._detect_transaction_events",
            side_effect=AssertionError("recognizer must be bypassed"),
        ):
            findings = _run_with(
                rows, [1, 2], ["rare-1", "rare-2"],
                {"recognize_transactions": False, "family_min_size": 3},
            )
        self.assertEqual([finding.title for finding in findings], ["rare-0", "rare-1"])

    def test_transaction_claim_window_is_inclusive_and_requires_whole_interval(self) -> None:
        event = _TransactionEvent(
            "admin session", "h", _BASE_TS + 100, _BASE_TS + 100,
            _BASE_TS + 100 - TRANSACTION_LEAD_TOLERANCE_SECONDS,
            _BASE_TS + 100 + TRANSACTION_TAIL_TOLERANCE_SECONDS,
            (_BASE_TS + 100,),
        )
        inside_left = _stored_needle(event.claim_start_ts, "h", "inside-left")
        inside_right = _stored_needle(event.claim_end_ts, "h", "inside-right")
        outside_left = _stored_needle(event.claim_start_ts - 1, "h", "outside-left")
        crossing = _make_burst_pair("h", event.claim_end_ts - 1, event.claim_end_ts + 1)

        result = _reconcile_transactions(
            [event], [inside_left, inside_right, outside_left, crossing],
            now=_NOW, data_window=_WINDOW,
        )

        transaction = next(finding for _, finding in result
                           if finding.evidence.get("tier") == "transaction")
        self.assertEqual(
            {member["title"] for member in transaction.evidence["members"]},
            {"inside-left", "inside-right"},
        )
        self.assertTrue(any(finding is outside_left[1] for _, finding in result))
        self.assertTrue(any(finding is crossing[1] for _, finding in result))

    def test_transaction_overlap_uses_nearest_anchor_then_earlier_event(self) -> None:
        first = _TransactionEvent(
            "admin session", "h", _BASE_TS + 100, _BASE_TS + 100,
            _BASE_TS, _BASE_TS + 300, (_BASE_TS + 100,),
        )
        second = _TransactionEvent(
            "update run", "h", _BASE_TS + 200, _BASE_TS + 200,
            _BASE_TS, _BASE_TS + 300, (_BASE_TS + 200,),
        )
        pairs = [
            _stored_needle(_BASE_TS + 150, "h", "exact-tie"),
            _stored_needle(_BASE_TS + 149, "h", "first-nearest"),
            _stored_needle(_BASE_TS + 190, "h", "second-nearest"),
            _stored_needle(_BASE_TS + 191, "h", "second-nearest-2"),
        ]

        result = _reconcile_transactions(
            [second, first], pairs, now=_NOW, data_window=_WINDOW
        )
        by_label = {
            finding.evidence["label"]: finding
            for _, finding in result
            if finding.evidence.get("tier") == "transaction"
        }
        self.assertEqual(
            {member["title"] for member in by_label["admin session"].evidence["members"]},
            {"exact-tie", "first-nearest"},
        )
        self.assertEqual(
            {member["title"] for member in by_label["update run"].evidence["members"]},
            {"second-nearest", "second-nearest-2"},
        )

    def test_transaction_reconciliation_conserves_all_stored_shapes_once(self) -> None:
        def aggregate(
            tier: str, title: str, start: float, end: float, count: int,
            *, program: str, privileged: bool = False,
        ) -> tuple[float, Finding]:
            evidence: dict[str, object] = {
                "tier": tier, "host": "h", "program": program,
                "line_count": count, "start_ts": start, "end_ts": end,
                "first_seen": datetime.fromtimestamp(start, timezone.utc).isoformat(),
                "program_mix": [[program, count]], "label": None,
            }
            if privileged:
                evidence["privileged"] = True
            return start, Finding(
                detector="syslog",
                severity=Severity.MEDIUM if privileged else (
                    Severity.INFO if tier == "burst" else Severity.LOW
                ),
                title=title, description="stored review unit", evidence=evidence,
                next_steps=[], ts_generated=_NOW, data_window=_WINDOW,
            )

        event = _TransactionEvent(
            "admin session", "h", _BASE_TS + 100, _BASE_TS + 200,
            _BASE_TS, _BASE_TS + 300, (_BASE_TS + 100, _BASE_TS + 200),
        )
        shapes = [
            aggregate("family", "h", _BASE_TS + 110, _BASE_TS + 120, 2,
                      program="useradd", privileged=True),
            _stored_needle(_BASE_TS + 130, "h", "member-needle",
                           program="sshd", privileged=True),
            aggregate("burst", "h", _BASE_TS + 140, _BASE_TS + 150, 3,
                      program="cron"),
            aggregate("family", "h", _BASE_TS + 160, _BASE_TS + 170, 2,
                      program="kernel"),
            _stored_needle(_BASE_TS + 180, "h", "sieve-needle", program="cron"),
        ]
        nan_member = _stored_needle(
            float("nan"), "h", "nan-member", program="sudo", privileged=True
        )
        reboot = _reboot_finding(
            _BootEvent("h", _BASE_TS + 150, _BASE_TS + 150, 1), _NOW, _WINDOW
        )

        result = _reconcile_transactions(
            [event], [*shapes, nan_member, reboot], now=_NOW, data_window=_WINDOW
        )

        transactions = [finding for _, finding in result
                        if finding.evidence.get("tier") == "transaction"]
        self.assertEqual(len(transactions), 1)
        transaction = transactions[0]
        self.assertEqual(transaction.evidence["member_count"], 5)
        self.assertEqual(transaction.evidence["represented_line_count"], 9)
        self.assertEqual(len(transaction.evidence["members"]), 5)
        self.assertEqual(sum(
            member["represented_line_count"]
            for member in transaction.evidence["members"]
        ), 9)
        self.assertTrue(any(finding is nan_member[1] for _, finding in result))
        self.assertTrue(any(finding is reboot[1] for _, finding in result))
        self.assertEqual(len(result), 3)

    def test_transaction_reconciliation_degrades_without_claimable_host(self) -> None:
        event = _TransactionEvent(
            "admin session", "expected", _BASE_TS, _BASE_TS + 1,
            _BASE_TS - 60, _BASE_TS + 121, (_BASE_TS, _BASE_TS + 1),
        )
        pairs = [
            _stored_needle(_BASE_TS, "other", "one"),
            _stored_needle(_BASE_TS + 1, "other", "two"),
        ]
        result = _reconcile_transactions(
            [event], pairs, now=_NOW, data_window=_WINDOW
        )
        self.assertEqual(len(result), 2)
        self.assertTrue(all(result[index][1] is pairs[index][1] for index in range(2)))

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
        rare = Finding(detector="syslog", severity=Severity.LOW, title="rare",
                         description="", evidence={"host": "h", "template_str": "t",
                         "count": 1, "threshold": 1}, next_steps=[],
                         ts_generated=_NOW, data_window=_WINDOW)
        burst = Finding(detector="syslog", severity=Severity.INFO, title="h",
                        description="", evidence={"tier": "burst", "line_count": 4,
                        "span_seconds": 1.0, "start_ts": 1.0, "end_ts": 2.0,
                        "program_mix": [["p", 4]], "sample_raw": ["a"], "label": None},
                        next_steps=[], ts_generated=_NOW, data_window=_WINDOW)
        family = Finding(detector="syslog", severity=Severity.LOW, title="h",
                         description="", evidence={"tier": "family", "host": "h",
                         "program": "p", "line_count": 2, "start_ts": 3.0,
                         "end_ts": 4.0, "span_seconds": 1.0,
                         "sample_raw": ["b", "c"], "label": None},
                         next_steps=[], ts_generated=_NOW, data_window=_WINDOW)
        fs = [rare, family, burst]
        for lvl in (0, 1, 2):
            r = _build_renderable("syslog", fs, lvl, 100)
            self.assertEqual(sum(len(s.findings) for s in r.sections), len(fs))

    # ── Text renderer ─────────────────────────────────────────────────────────

    def test_text_renderer_syslog_group(self) -> None:
        """Needles lead bursts; aggregate rows use the shared display timestamp."""
        from sigwood.outputs.text import TextHandler
        from sigwood.outputs._render_model import _partition_syslog

        privileged_f = Finding(
            detector="syslog",
            severity=Severity.MEDIUM,
            title="May 30 14:23:01 router sshd[100]: Failed password for root",
            description="Rare template",
            evidence={
                "host": "router", "template_id": 47,
                "template_str": "sshd[*]: Failed password for <*>",
                "count": 1, "threshold": 3, "privileged": True,
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
            handler._render_syslog_group(_partition_syslog([privileged_f, reboot_f]))
        )

        # Section labels with pre-cap counts, privileged events leading.
        self.assertIn("privileged (1)", joined)
        self.assertIn("bursts (1)", joined)
        self.assertLess(joined.index("privileged"), joined.index("bursts"))
        # MEDIUM needle: raw line, template/count internals stay behind -v.
        self.assertIn("May 30 14:23:01 router sshd[100]", joined)
        self.assertNotIn("count=", joined)
        self.assertNotIn("template_id", joined)
        # Reboot line leads with the display-timezone timestamp from evidence.
        self.assertIn("May 30 02:14:00 · host1 · rebooted", joined)

    def test_text_renderer_transaction_summary_and_verbose_members(self) -> None:
        from sigwood.outputs._render_model import _partition_syslog
        from sigwood.outputs.text import TextHandler

        transaction = Finding(
            detector="syslog", severity=Severity.MEDIUM, title="host-a",
            description="Recognized administrative session activity.",
            evidence={
                "tier": "transaction", "label": "admin session", "host": "host-a",
                "member_count": 2, "represented_line_count": 3,
                "start_ts": _BASE_TS, "end_ts": _BASE_TS + 120,
                "first_seen": datetime.fromtimestamp(_BASE_TS, timezone.utc).isoformat(),
                "span_seconds": 120.0, "program_mix": [["useradd", 2], ["cron", 1]],
                "members": [
                    {"severity": "medium", "tier": "family",
                     "represented_line_count": 2, "program": "useradd",
                     "title": "safe\x1b<script>member</script>", "privileged": True},
                    {"severity": "low", "tier": "needle",
                     "represented_line_count": 1, "program": "cron",
                     "title": "second-member"},
                ],
                "privileged": True,
            },
            next_steps=["Review the member findings"],
            ts_generated=_NOW, data_window=_WINDOW,
        )
        sections = _partition_syslog([transaction])
        self.assertEqual([(section.label, len(section.findings)) for section in sections], [
            ("privileged", 1),
        ])

        level_zero = "\n".join(
            TextHandler(verbose_level=0)._render_syslog_group(sections)
        )
        self.assertIn(
            "host-a · admin session · 2 member findings · 2m · mostly useradd, cron",
            level_zero,
        )
        self.assertNotIn("second-member", level_zero)

        for level in (1, 2):
            rendered = "\n".join(
                TextHandler(verbose_level=level)._render_syslog_group(sections)
            )
            self.assertEqual(rendered.count("members:"), 1)
            self.assertIn("[M] · useradd · family · 2 rare lines", rendered)
            self.assertIn("safe<script>member</script>", rendered)
            self.assertIn("[L] · cron · needle · 1 rare line", rendered)
            self.assertNotIn("{'severity'", rendered)
            self.assertNotIn("\x1b", rendered)

    def test_text_renderer_member_fragments_once_at_every_level(self) -> None:
        from sigwood.outputs.text import TextHandler

        finding = Finding(
            detector="syslog", severity=Severity.LOW, title="host-family",
            description="A set of rare log lines.",
            evidence={
                "tier": "family", "host": "host-family", "program": "kernel",
                "line_count": 2, "start_ts": 1.0, "end_ts": 2.0,
                "span_seconds": 1.0, "sample_raw": ["raw-a", "raw-b"],
                "member_fragments": ["fragment-one", "safe\x1b\x07\x9b-fragment"],
                "label": None,
            },
            next_steps=[], ts_generated=_NOW, data_window=_WINDOW,
        )
        for level in (0, 1, 2):
            rendered = "\n".join(
                TextHandler(verbose_level=level)._render_syslog_group(
                    _flat_section([finding])
                )
            )
            self.assertIn("\n        fragment-one", rendered)
            self.assertIn("\n        safe-fragment", rendered)
            self.assertEqual(rendered.count("fragment-one"), 1)
            self.assertNotIn("member_fragments:", rendered)
            for control in ("\x1b", "\x07", "\x9b"):
                self.assertNotIn(control, rendered)

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
                "count": 1, "threshold": 3, "privileged": True,
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

    def test_text_syslog_low_is_visible_at_level_zero(self) -> None:
        from sigwood.outputs.text import TextHandler
        from sigwood.outputs._render_model import _partition_syslog

        low = Finding(
            detector="syslog", severity=Severity.LOW, title="low-sentinel",
            description="", evidence={"host": "h", "program_total": 1,
                                       "template_str": "t", "count": 1, "threshold": 1},
            next_steps=[], ts_generated=_NOW, data_window=_WINDOW,
        )
        rendered = "\n".join(
            TextHandler(verbose_level=0)._render_syslog_group(_partition_syslog([low]))
        )
        self.assertIn("rare events (1)", rendered)
        self.assertIn("[L]", rendered)
        self.assertIn("low-sentinel", rendered)

    def test_needle_stamp_facts_split_curated_and_debug_text_levels(self) -> None:
        from sigwood.outputs._render_model import _partition_syslog
        from sigwood.outputs.text import TextHandler

        needle = Finding(
            detector="syslog", severity=Severity.LOW, title="bare journal payload",
            description="Rare template", evidence={
                "host": "h", "program": "cron", "program_total": 1,
                "template_id": 7, "template_str": "cron: bare journal payload",
                "count": 1, "threshold": 1,
                "first_seen": "2026-07-12T21:57:33+00:00",
                "self_stamped": False,
            }, next_steps=[], ts_generated=_NOW, data_window=_WINDOW,
        )
        at1 = "\n".join(
            TextHandler(verbose_level=1)._render_syslog_group(
                _partition_syslog([needle])
            )
        )
        at2 = "\n".join(
            TextHandler(verbose_level=2)._render_syslog_group(
                _partition_syslog([needle])
            )
        )
        self.assertIn("first_seen: 2026-07-12T21:57:33+00:00", at1)
        self.assertNotIn("self_stamped:", at1)
        self.assertIn("first_seen: 2026-07-12T21:57:33+00:00", at2)
        self.assertIn("self_stamped: False", at2)

    def test_text_level_one_samples_three_and_level_two_keeps_full(self) -> None:
        from sigwood.outputs.text import TextHandler
        from sigwood.outputs._render_model import _partition_syslog

        samples = [f"raw-sample-{i}" for i in range(5)]
        family = Finding(
            detector="syslog", severity=Severity.LOW, title="h",
            description="Family detail.", evidence={
                "tier": "family", "host": "h", "program": "kernel",
                "line_count": 5, "program_total": 500, "start_ts": _BASE_TS,
                "end_ts": _BASE_TS + 4, "first_seen": "2025-05-30T00:00:00+00:00",
                "span_seconds": 4.0, "sample_raw": samples, "label": None,
            }, next_steps=[], ts_generated=_NOW, data_window=_WINDOW,
        )
        at1 = "\n".join(
            TextHandler(verbose_level=1)._render_syslog_group(_partition_syslog([family]))
        )
        at2 = "\n".join(
            TextHandler(verbose_level=2)._render_syslog_group(_partition_syslog([family]))
        )
        self.assertIn("raw-sample-0", at1)
        self.assertIn("raw-sample-2", at1)
        self.assertNotIn("raw-sample-3", at1)
        self.assertIn("sample_raw:\n         · raw-sample-0", at1)
        self.assertNotIn("['raw-sample-0'", at1)
        self.assertIn("raw-sample-4", at2)

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
    assert any(f.severity == Severity.LOW for f in findings)


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


def test_journal_needle_runs_to_time_anchored_text() -> None:
    from sigwood.outputs._render_model import _partition_syslog
    from sigwood.outputs.text import TextHandler

    parsed = parse_journal_record(json.dumps({
        "__REALTIME_TIMESTAMP": "1760000000000000",
        "MESSAGE": "journal needle sentinel",
        "_HOSTNAME": "host.example",
        "SYSLOG_IDENTIFIER": "cron",
    }))
    assert isinstance(parsed, dict)

    findings = _run_with(
        [parsed], [1], ["cron: journal needle sentinel"],
    )
    assert len(findings) == 1
    needle = findings[0]
    assert needle.title == "journal needle sentinel"
    assert needle.evidence["first_seen"] == "2025-10-09T08:53:20+00:00"
    assert needle.evidence["self_stamped"] is False

    rendered = "\n".join(
        TextHandler(verbose_level=0)._render_syslog_group(
            _partition_syslog(findings)
        )
    )
    assert "[L]   Oct  9 08:53:20 · journal needle sentinel" in rendered


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
