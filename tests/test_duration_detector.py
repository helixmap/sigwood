"""Tests for the duration detector.

All IP addresses use RFC 5737 documentation space:
  192.0.2.x, 198.51.100.x, 203.0.113.x
"""

from __future__ import annotations

import io
import unittest

from tests.test_voice_consistency import assert_report_voice
from datetime import datetime, timezone

import pandas as pd

from sigwood.common.finding import DetectorContext, Finding, RunSummary, Severity
from sigwood.detectors.duration import (
    DETECTOR_NAME,
    STATUS,
    _duration_str,
    _is_non_unicast_dst,
    run,
)
from sigwood.outputs.text import TextHandler
from sigwood.runner import discover_detectors


# ── Helpers ───────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 5, 30, tzinfo=timezone.utc)
_WINDOW = (_NOW, _NOW)


def _ctx(
    df: pd.DataFrame | None,
    cfg: dict | None = None,
) -> DetectorContext:
    logs = {"conn*.log*": df} if df is not None else {}
    return DetectorContext(
        logs=logs,
        config=cfg or {},
        allowlist=None,
        data_window=_WINDOW,
    )


def _conn_row(
    src: str = "192.0.2.10",
    dst: str = "198.51.100.20",
    port: int = 443,
    proto: str = "tcp",
    duration: float = 7200.0,
    ts: float = 1_779_750_000.0,
    **kwargs,
) -> dict:
    row = {
        "src": src, "dst": dst, "port": port, "proto": proto,
        "duration": duration, "ts": ts,
    }
    row.update(kwargs)
    return row


def _minimal_finding() -> Finding:
    return Finding(
        detector="duration",
        severity=Severity.MEDIUM,
        title="192.0.2.10 → 198.51.100.20:443/tcp",
        description="A long-lived connection.",
        evidence={
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "port": 443,
            "proto": "tcp",
            "max_duration_seconds": 7200.0,
            "max_duration_str": "2h 0m",
            "connection_count": 1,
            "total_bytes": None,
            "avg_bytes_per_second": None,
            "conn_states": [],
            "first_seen": None,
            "last_seen": None,
        },
        next_steps=["Review the connection."],
        ts_generated=_NOW,
        data_window=_WINDOW,
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

class DurationDetectorTests(unittest.TestCase):

    # ── Discovery ─────────────────────────────────────────────────────────────

    def test_duration_is_available_in_discover_detectors(self) -> None:
        detectors = discover_detectors()
        self.assertIn("duration", detectors)
        self.assertEqual(getattr(detectors["duration"], "STATUS", None), "available")

    def test_detector_name_and_status_constants(self) -> None:
        self.assertEqual(DETECTOR_NAME, "duration")
        self.assertEqual(STATUS, "available")

    # ── Empty / missing input ─────────────────────────────────────────────────

    def test_run_returns_empty_when_no_conn_key(self) -> None:
        self.assertEqual(run(_ctx(None)), [])

    def test_run_returns_empty_on_empty_dataframe(self) -> None:
        empty = pd.DataFrame(columns=["src", "dst", "port", "proto", "ts", "duration"])
        self.assertEqual(run(_ctx(empty)), [])

    def test_run_returns_empty_when_duration_column_absent(self) -> None:
        df = pd.DataFrame([{"src": "192.0.2.10", "dst": "198.51.100.20",
                            "port": 443, "proto": "tcp", "ts": 1_779_750_000.0}])
        self.assertEqual(run(_ctx(df)), [])

    def test_run_returns_empty_when_all_below_threshold(self) -> None:
        df = pd.DataFrame([_conn_row(duration=299.0)])
        self.assertEqual(run(_ctx(df, {"min_duration_seconds": 300})), [])

    def test_run_returns_empty_when_all_nan(self) -> None:
        df = pd.DataFrame([_conn_row(duration=float("nan"))])
        self.assertEqual(run(_ctx(df)), [])

    def test_run_returns_empty_when_all_zero(self) -> None:
        df = pd.DataFrame([_conn_row(duration=0.0)])
        self.assertEqual(run(_ctx(df)), [])

    def test_run_returns_empty_when_all_negative(self) -> None:
        df = pd.DataFrame([_conn_row(duration=-10.0)])
        self.assertEqual(run(_ctx(df)), [])

    # ── Core detection ────────────────────────────────────────────────────────

    def test_medium_severity_at_7200s(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        findings = run(_ctx(df))
        assert_report_voice(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_high_severity_at_14400s(self) -> None:
        df = pd.DataFrame([_conn_row(duration=14400.0)])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_high_severity_above_14400s(self) -> None:
        df = pd.DataFrame([_conn_row(duration=86400.0)])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_non_unicast_long_flow_is_low_with_neutral_prose(self) -> None:
        df = pd.DataFrame([
            _conn_row(
                dst="239.255.255.250",
                port=1900,
                proto="udp",
                duration=18000.0,
                conn_state="S0",
            )
        ])
        findings = run(_ctx(df))
        assert_report_voice(findings)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity, Severity.LOW)
        prose = finding.description.lower()
        self.assertNotIn("c2", prose)
        self.assertNotIn("exfil", prose)
        self.assertNotIn("tunneling", prose)
        self.assertFalse(any("whois" in step.lower() for step in finding.next_steps))

    def test_external_unicast_long_flow_stays_high(self) -> None:
        df = pd.DataFrame([
            _conn_row(
                dst="203.0.113.9",
                duration=18000.0,
                conn_state="SF",
            )
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertTrue(any("whois 203.0.113.9" in step for step in findings[0].next_steps))

    def test_local_command_step_quotes_hostile_source(self) -> None:
        findings = run(_ctx(pd.DataFrame([
            _conn_row(
                src="192.0.2.10;id",
                dst="239.255.255.250",
                port=1900,
                proto="udp",
            )
        ])))

        assert_report_voice(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].next_steps[0],
            "Review 2h 0m connection in conn.log: zeek-cut id.orig_h id.resp_h "
            "id.resp_p duration conn_state < conn.log | grep '192.0.2.10;id'",
        )

    def test_external_command_steps_quote_hostile_endpoints(self) -> None:
        findings = run(_ctx(pd.DataFrame([
            _conn_row(
                src="2001:db8::10;id",
                dst="203.0.113.9;id",
            )
        ])))

        assert_report_voice(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].next_steps[0],
            "Review 2h 0m connection in conn.log: zeek-cut id.orig_h id.resp_h "
            "id.resp_p duration conn_state < conn.log | grep '2001:db8::10;id'",
        )
        self.assertEqual(
            findings[0].next_steps[2],
            "Check the destination: whois '203.0.113.9;id'",
        )

    def test_command_steps_preserve_safe_endpoint_bytes(self) -> None:
        local = run(_ctx(pd.DataFrame([
            _conn_row(
                src="192.0.2.10",
                dst="239.255.255.250",
                port=1900,
                proto="udp",
            )
        ])))[0]
        external = run(_ctx(pd.DataFrame([
            _conn_row(
                src="2001:db8::10",
                dst="203.0.113.9",
            )
        ])))[0]

        assert_report_voice([local, external])
        self.assertEqual(
            local.next_steps[0],
            "Review 2h 0m connection in conn.log: zeek-cut id.orig_h id.resp_h "
            "id.resp_p duration conn_state < conn.log | grep 192.0.2.10",
        )
        self.assertEqual(
            external.next_steps[0],
            "Review 2h 0m connection in conn.log: zeek-cut id.orig_h id.resp_h "
            "id.resp_p duration conn_state < conn.log | grep 2001:db8::10",
        )
        self.assertEqual(
            external.next_steps[2],
            "Check the destination: whois 203.0.113.9",
        )

    def test_numeric_and_nan_group_keys_remain_renderable(self) -> None:
        """Non-string keys are a green-at-HEAD neutrality control."""
        findings = run(_ctx(pd.DataFrame([
            _conn_row(src=123.5, dst=float("nan"))  # type: ignore[arg-type]
        ])))

        assert_report_voice(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].next_steps[0],
            "Review 2h 0m connection in conn.log: zeek-cut id.orig_h id.resp_h "
            "id.resp_p duration conn_state < conn.log | grep 123.5",
        )
        self.assertEqual(
            findings[0].next_steps[2],
            "Check the destination: whois nan",
        )

    def test_non_unicast_helper_fails_open_for_non_ip_values(self) -> None:
        self.assertTrue(_is_non_unicast_dst("239.255.255.250"))
        self.assertTrue(_is_non_unicast_dst("255.255.255.255"))
        self.assertTrue(_is_non_unicast_dst("169.254.1.2"))
        self.assertTrue(_is_non_unicast_dst("fe80::1"))
        self.assertFalse(_is_non_unicast_dst("198.51.100.255"))
        self.assertFalse(_is_non_unicast_dst("not-an-ip"))
        self.assertFalse(_is_non_unicast_dst(None))  # type: ignore[arg-type]

    def test_low_severity_at_301s_emitted(self) -> None:
        df = pd.DataFrame([_conn_row(duration=301.0)])
        findings = run(_ctx(df, {"min_duration_seconds": 300}))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)

    def test_exactly_at_threshold_is_detected(self) -> None:
        df = pd.DataFrame([_conn_row(duration=1800.0)])
        # 1800s is LOW (< 7200) - the result set is verbosity-invariant,
        # so LOW always emits; the text handler is responsible for hiding LOW at
        # level 0.
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)

    def test_just_below_threshold_not_detected(self) -> None:
        df = pd.DataFrame([_conn_row(duration=1799.9)])
        self.assertEqual(run(_ctx(df)), [])

    def test_multiple_findings_sorted_descending_by_max_duration(self) -> None:
        df = pd.DataFrame([
            _conn_row(src="192.0.2.10", duration=7200.0),
            _conn_row(src="192.0.2.11", duration=14400.0),
            _conn_row(src="192.0.2.12", duration=9000.0),
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 3)
        durations = [f.evidence["max_duration_seconds"] for f in findings]
        self.assertEqual(durations, sorted(durations, reverse=True))
        self.assertEqual(findings[0].evidence["src"], "192.0.2.11")

    def test_zero_duration_excluded_even_if_column_present(self) -> None:
        df = pd.DataFrame([
            _conn_row(src="192.0.2.10", duration=0.0),
            _conn_row(src="192.0.2.11", duration=7200.0),
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["src"], "192.0.2.11")

    def test_non_numeric_duration_values_tolerated(self) -> None:
        df = pd.DataFrame([
            _conn_row(src="192.0.2.10", duration="bad"),
            _conn_row(src="192.0.2.11", duration=7200.0),
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["src"], "192.0.2.11")

    # ── Grouping behavior ─────────────────────────────────────────────────────

    def test_grouping_collapses_same_flow(self) -> None:
        # Three rows for the same (src, dst, port, proto) → one finding
        df = pd.DataFrame([
            _conn_row(duration=7200.0,  ts=1_779_750_000.0),
            _conn_row(duration=9000.0,  ts=1_779_750_100.0),
            _conn_row(duration=7800.0,  ts=1_779_750_200.0),
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["connection_count"], 3)
        self.assertEqual(findings[0].evidence["max_duration_seconds"], 9000.0)

    def test_floor_row_excluded_from_group(self) -> None:
        # One row below the floor; only the two above it count
        df = pd.DataFrame([
            _conn_row(duration=7200.0),
            _conn_row(duration=9000.0),
            _conn_row(duration=500.0),   # below default 1800s floor
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["connection_count"], 2)
        self.assertEqual(findings[0].evidence["max_duration_seconds"], 9000.0)

    def test_two_flows_produce_two_findings(self) -> None:
        df = pd.DataFrame([
            _conn_row(src="192.0.2.10", dst="198.51.100.1", port=443,  duration=7200.0),
            _conn_row(src="192.0.2.10", dst="198.51.100.2", port=443,  duration=14400.0),
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 2)

    # ── LOW severity: result-set verbosity invariance ─────────────────────────

    def test_low_always_emitted_result_set_invariant(self) -> None:
        """duration.run() emits LOW findings regardless of verbosity. The
        result set is invariant across verbose levels; the text handler is the
        sole authority on hiding LOW at level 0 (the render pipeline's level-filter step)."""
        # 2000s is LOW (< 7200) but above the 1800s floor.
        df = pd.DataFrame([_conn_row(duration=2000.0)])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)

    # ── Evidence fields ───────────────────────────────────────────────────────

    def test_max_duration_seconds_is_rounded_float(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.123456)])
        f = run(_ctx(df))[0]
        self.assertEqual(f.evidence["max_duration_seconds"], 7200.1)

    def test_max_duration_str_present_and_non_empty(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        f = run(_ctx(df))[0]
        self.assertIsInstance(f.evidence["max_duration_str"], str)
        self.assertTrue(f.evidence["max_duration_str"])

    def test_src_dst_port_proto_present(self) -> None:
        df = pd.DataFrame([_conn_row(
            src="192.0.2.10", dst="198.51.100.20", port=443, proto="tcp", duration=7200.0
        )])
        f = run(_ctx(df))[0]
        self.assertEqual(f.evidence["src"], "192.0.2.10")
        self.assertEqual(f.evidence["dst"], "198.51.100.20")
        self.assertEqual(f.evidence["port"], 443)
        self.assertEqual(f.evidence["proto"], "tcp")

    def test_avg_bps_none_when_bytes_null(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        f = run(_ctx(df))[0]
        self.assertIsNone(f.evidence["avg_bytes_per_second"])

    def test_avg_bps_computed_when_bytes_present(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0, bytes=720000)])
        f = run(_ctx(df))[0]
        self.assertIsNotNone(f.evidence["avg_bytes_per_second"])
        self.assertAlmostEqual(f.evidence["avg_bytes_per_second"], 100.0, places=1)

    def test_avg_bps_from_max_duration_row(self) -> None:
        # Row 1: max duration 9000s, bytes 90000 → bps 10.0
        # Row 2: shorter duration 7200s, bytes 720000 (higher bytes, shorter duration)
        # avg_bps must use the max-duration row: 90000 / 9000 = 10.0
        df = pd.DataFrame([
            _conn_row(duration=9000.0, bytes=90000),
            _conn_row(duration=7200.0, bytes=720000),
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0].evidence["avg_bytes_per_second"], 10.0, places=1)

    def test_avg_bps_none_when_column_absent(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        self.assertNotIn("bytes", df.columns)
        f = run(_ctx(df))[0]
        self.assertIsNone(f.evidence["avg_bytes_per_second"])

    def test_total_bytes_none_when_all_null(self) -> None:
        df = pd.DataFrame([
            _conn_row(duration=7200.0, bytes=None),
            _conn_row(duration=7800.0, bytes=float("nan")),
        ])
        findings = run(_ctx(df))
        self.assertIsNone(findings[0].evidence["total_bytes"])

    def test_total_bytes_none_when_column_absent(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        self.assertNotIn("bytes", df.columns)
        f = run(_ctx(df))[0]
        self.assertIsNone(f.evidence["total_bytes"])

    def test_conn_states_when_single_state_present(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0, conn_state="SF")])
        f = run(_ctx(df))[0]
        self.assertEqual(f.evidence["conn_states"], ["SF"])

    def test_conn_states_distinct_sorted(self) -> None:
        # Repeated and null states - expect sorted unique non-null list
        df = pd.DataFrame([
            _conn_row(duration=8000.0, conn_state="SF"),
            _conn_row(duration=7800.0, conn_state="RSTO"),
            _conn_row(duration=7200.0, conn_state="SF"),    # duplicate
            _conn_row(duration=7500.0, conn_state=None),    # null, excluded
        ])
        findings = run(_ctx(df))
        self.assertEqual(findings[0].evidence["conn_states"], ["RSTO", "SF"])

    def test_conn_states_empty_list_when_column_absent(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        self.assertNotIn("conn_state", df.columns)
        f = run(_ctx(df))[0]
        self.assertEqual(f.evidence["conn_states"], [])

    # ── Finding contract ──────────────────────────────────────────────────────

    def test_title_contains_src_and_dst_port(self) -> None:
        df = pd.DataFrame([_conn_row(
            src="192.0.2.10", dst="198.51.100.20", port=443, proto="tcp", duration=7200.0
        )])
        f = run(_ctx(df))[0]
        self.assertIn("192.0.2.10", f.title)
        self.assertIn("198.51.100.20", f.title)
        self.assertIn("443", f.title)

    def test_title_does_not_contain_duration_value(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        f = run(_ctx(df))[0]
        self.assertNotIn("7200", f.title)
        self.assertNotIn("2h", f.title)

    def test_detector_field_is_duration(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        f = run(_ctx(df))[0]
        self.assertEqual(f.detector, "duration")

    def test_next_steps_non_empty(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        f = run(_ctx(df))[0]
        self.assertIsInstance(f.next_steps, list)
        self.assertGreater(len(f.next_steps), 0)

    # ── _duration_str helper ──────────────────────────────────────────────────

    def test_duration_str_seconds(self) -> None:
        self.assertEqual(_duration_str(47.0), "47s")

    def test_duration_str_minutes(self) -> None:
        self.assertEqual(_duration_str(872.0), "14m 32s")

    def test_duration_str_hours(self) -> None:
        self.assertEqual(_duration_str(15780.0), "4h 23m")

    def test_duration_str_days(self) -> None:
        self.assertEqual(_duration_str(93600.0), "1d 2h")

    # ── Text renderer ─────────────────────────────────────────────────────────

    def test_render_duration_group_no_exception(self) -> None:
        summary = RunSummary(
            data_window=_WINDOW,
            record_counts={"conn*.log*": 1},
            data_size_bytes=0,
            detectors_run=["duration"],
            detectors_skipped={},
        )
        stream = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=0)
        handler.begin(summary)
        handler.write([_minimal_finding()])
        handler.end()
        self.assertTrue(len(stream.getvalue()) > 0)

    def test_render_output_contains_key_tokens(self) -> None:
        df = pd.DataFrame([_conn_row(
            src="192.0.2.10", dst="198.51.100.20", port=443, proto="tcp", duration=7200.0
        )])
        findings = run(_ctx(df))
        summary = RunSummary(
            data_window=_WINDOW, record_counts={}, data_size_bytes=0,
            detectors_run=["duration"], detectors_skipped={},
        )
        stream = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=0)
        handler.begin(summary)
        handler.write(findings)
        handler.end()
        output = stream.getvalue()
        self.assertIn("192.0.2.10", output)
        self.assertIn("198.51.100.20", output)
        self.assertIn("2h 0m", output)

    def test_verbose_mode_emits_evidence_and_next_steps(self) -> None:
        summary = RunSummary(
            data_window=_WINDOW, record_counts={}, data_size_bytes=0,
            detectors_run=["duration"], detectors_skipped={},
        )
        stream = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=1)
        handler.begin(summary)
        handler.write([_minimal_finding()])
        handler.end()
        output = stream.getvalue()
        self.assertIn("evidence:", output)
        self.assertIn("next steps:", output)
        self.assertIn("data window:", output)

    def test_render_conns_column_pluralization(self) -> None:
        # Two rows with the same flow tuple → grouped → "2 conns"
        df = pd.DataFrame([
            _conn_row(duration=7200.0, ts=1_779_750_000.0),
            _conn_row(duration=7800.0, ts=1_779_750_100.0),
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 1)
        summary = RunSummary(
            data_window=_WINDOW, record_counts={}, data_size_bytes=0,
            detectors_run=["duration"], detectors_skipped={},
        )
        stream = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=0)
        handler.begin(summary)
        handler.write(findings)
        handler.end()
        self.assertIn("conns", stream.getvalue())

    def test_render_single_conn_uses_singular(self) -> None:
        df = pd.DataFrame([_conn_row(duration=7200.0)])
        findings = run(_ctx(df))
        summary = RunSummary(
            data_window=_WINDOW, record_counts={}, data_size_bytes=0,
            detectors_run=["duration"], detectors_skipped={},
        )
        stream = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=0)
        handler.begin(summary)
        handler.write(findings)
        handler.end()
        self.assertIn("1 conn", stream.getvalue())

    def test_arrow_alignment_across_multiple_findings(self) -> None:
        """All → arrows must appear at the same column offset."""
        df = pd.DataFrame([
            _conn_row(src="192.0.2.10",  dst="198.51.100.1",   port=443,   duration=14400.0),
            _conn_row(src="192.0.2.200", dst="203.0.113.5",    port=22,    duration=7200.0),
            _conn_row(src="192.0.2.1",   dst="198.51.100.200", port=9997,  duration=7201.0),
        ])
        findings = run(_ctx(df))
        self.assertEqual(len(findings), 3)

        summary = RunSummary(
            data_window=_WINDOW, record_counts={}, data_size_bytes=0,
            detectors_run=["duration"], detectors_skipped={},
        )
        stream = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=0)
        handler.begin(summary)
        handler.write(findings)
        handler.end()

        output_lines = stream.getvalue().splitlines()
        finding_lines = [line for line in output_lines if line.lstrip().startswith("[")]
        arrow_positions = [line.index("→") for line in finding_lines if "→" in line]
        self.assertEqual(len(arrow_positions), 3)
        self.assertEqual(len(set(arrow_positions)), 1, (
            f"→ arrows not aligned - positions: {arrow_positions}"
        ))


if __name__ == "__main__":
    unittest.main()
