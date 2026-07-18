"""Focused tests for the scan detector migration.

All IP addresses use RFC 5737 documentation space:
  192.0.2.x, 198.51.100.x, 203.0.113.x
"""

from __future__ import annotations

import io
import json
import sys

from tests.test_voice_consistency import assert_report_voice
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

from sigwood import cli
from sigwood.common import config as cfg
from sigwood.common.finding import DetectorContext, Finding, RunSummary, Severity
from sigwood.detectors.scan import (
    DETECTOR_NAME,
    STATUS,
    _classify_direction,
    _detect_horizontal,
    _detect_vertical,
    _make_finding,
    _zone_of,
    run,
)
from sigwood.outputs.text import TextHandler
from sigwood.runner import discover_detectors


# ── Helpers ───────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 5, 30, tzinfo=timezone.utc)
_WINDOW = (_NOW, _NOW)

# Matches the shipped [sigwood].home_net default. Used here only so a
# helper-built context behaves identically to a runner-built context for the
# detector's RFC 5737 doc-space traffic fixtures - those addresses are outside
# RFC1918 and read as external→external.
_RFC1918_HOME_NET = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def _ctx(
    df: pd.DataFrame | None,
    cfg: dict | None = None,
    home_net: list[str] | None = None,
) -> DetectorContext:
    """Build a DetectorContext for scan tests.

    home_net distinguishes None (apply RFC1918 default - same as runner supply
    path with no operator override) from [] (intentionally empty, to exercise
    the scan module's standalone-callable fallback constant). Tests that need
    a specific zone layout pass home_net explicitly.
    """
    logs = {"conn*.log*": df} if df is not None else {}
    return DetectorContext(
        logs=logs,
        config=cfg or {},
        allowlist=None,
        data_window=_WINDOW,
        home_net=_RFC1918_HOME_NET if home_net is None else home_net,
    )


def _base_row(scan_type: str, src: str = "192.0.2.1") -> dict:
    """Minimal classified result dict suitable for _make_finding."""
    return {
        "scan_type"        : scan_type,
        "src"              : src,
        "dst"              : "198.51.100.1" if scan_type == "vertical" else None,
        "port"             : 22 if scan_type == "horizontal" else None,
        "distinct_ports"   : 20,
        "distinct_hosts"   : 20,
        "total_conns"      : 100,
        "scan_state_ratio" : 0.70,
        "top_states"       : "S0, REJ",
        "direction"        : "internal→external",
        "pattern_tag"      : "confirmed_scan",
        "pattern_notes"    : "Strong scanner signature.",
        "window_start"     : "2026-05-30 00:00:00",
        "window_secs"      : 3600,
        "active_buckets"   : 5 if scan_type == "slow" else None,
        "temporal_spread_score": 2.5 if scan_type == "slow" else None,
        "max_ports_in_bucket"  : 4 if scan_type == "slow" else None,
        "_severity"        : Severity.HIGH,
    }


def _conn_df(
    src: str,
    dst: str | None,
    ports: list[int],
    dsts: list[str] | None,
    conn_state: str,
    proto: str = "tcp",
    base_ts: float = 1_748_563_200.0,
    spacing: float = 60.0,
) -> pd.DataFrame:
    """Build a canonical-schema DataFrame for detector input."""
    rows = []
    if dsts is not None:
        # horizontal - one port, many hosts
        p = ports[0]
        for i, d in enumerate(dsts):
            rows.append({
                "src"       : src,
                "dst"       : d,
                "port"      : p,
                "proto"     : proto,
                "ts"        : base_ts + i * spacing,
                "conn_state": conn_state,
            })
    else:
        # vertical - one host, many ports
        for i, p in enumerate(ports):
            rows.append({
                "src"       : src,
                "dst"       : dst,
                "port"      : p,
                "proto"     : proto,
                "ts"        : base_ts + i * spacing,
                "conn_state": conn_state,
            })
    return pd.DataFrame(rows)


def _helper_frame(rows: list[dict]) -> pd.DataFrame:
    """Build helper-level input with the direction column supplied by prefiltering."""
    frame = pd.DataFrame(rows)
    frame["direction"] = "external→external"
    return frame


def _zeek_conn(
    *,
    ts: float,
    src: str,
    dst: str,
    port: int,
    state: str,
) -> dict:
    """Build one tagged Zeek conn record for real-route regression corpora."""
    return {
        "_path": "conn",
        "ts": ts,
        "id.orig_h": src,
        "id.orig_p": 40000,
        "id.resp_h": dst,
        "id.resp_p": port,
        "proto": "tcp",
        "conn_state": state,
        "local_orig": True,
    }


def _write_conn_log(path: Path, rows: list[dict]) -> None:
    """Write a tagged Zeek NDJSON conn log."""
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )


def _write_scan_config(path: Path, *, vertical: int, horizontal: int) -> None:
    """Write scan tuning that isolates one scan type in a real-route test."""
    path.write_text(
        "\n".join([
            "[detectors.scan]",
            f"vertical_threshold = {vertical}",
            f"horizontal_threshold = {horizontal}",
            "block_port_threshold = 999",
            "block_host_threshold = 999",
            "slow_min_ports = 999",
            "window_secs = 60",
            "",
        ]),
        encoding="utf-8",
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

class ScanDetectorTests(unittest.TestCase):

    # ── Discovery ─────────────────────────────────────────────────────────────

    def test_scan_is_available_in_discover_detectors(self) -> None:
        detectors = discover_detectors()
        self.assertIn("scan", detectors)
        self.assertEqual(getattr(detectors["scan"], "STATUS", None), "available")

    def test_detector_name_constant(self) -> None:
        self.assertEqual(DETECTOR_NAME, "scan")
        self.assertEqual(STATUS, "available")

    # ── Empty / no input ──────────────────────────────────────────────────────

    def test_run_returns_empty_on_no_logs(self) -> None:
        self.assertEqual(run(_ctx(None)), [])

    def test_run_returns_empty_on_empty_dataframe(self) -> None:
        empty = pd.DataFrame(columns=["src", "dst", "port", "proto", "ts", "conn_state"])
        self.assertEqual(run(_ctx(empty)), [])

    def test_icmp_rows_excluded(self) -> None:
        df = _conn_df("192.0.2.1", "198.51.100.1",
                      ports=list(range(1, 30)), dsts=None,
                      conn_state="S0", proto="icmp")
        self.assertEqual(run(_ctx(df)), [])

    def test_malformed_but_loadable_rows_do_not_crash(self) -> None:
        """Missing nullable-ish fields and string ports should be normalized safely."""
        rows = []
        for i, port in enumerate(range(1, 25)):
            rows.append({
                "src" : "192.0.2.1",
                "dst" : None if i == 0 else "198.51.100.1",
                "port": str(port),
                "ts"  : 1_748_563_200.0 + i,
            })
        findings = run(_ctx(pd.DataFrame(rows), {"vertical_threshold": 15}))

        self.assertIsInstance(findings, list)

    def test_missing_port_column_returns_no_findings(self) -> None:
        rows = []
        for i in range(20):
            rows.append({
                "src"       : "192.0.2.1",
                "dst"       : "198.51.100.1",
                "proto"     : "tcp",
                "ts"        : 1_748_563_200.0 + i,
                "conn_state": "S0",
            })
        self.assertEqual(run(_ctx(pd.DataFrame(rows))), [])

    def test_missing_ts_column_returns_no_findings(self) -> None:
        rows = []
        for port in range(1, 25):
            rows.append({
                "src"       : "192.0.2.1",
                "dst"       : "198.51.100.1",
                "port"      : port,
                "proto"     : "tcp",
                "conn_state": "S0",
            })
        self.assertEqual(run(_ctx(pd.DataFrame(rows))), [])

    # ── Vertical scan ─────────────────────────────────────────────────────────

    def test_vertical_scan_detected(self) -> None:
        ports = list(range(1, 26))              # 25 distinct ports > threshold 15
        df = _conn_df(
            src="192.0.2.1",
            dst="198.51.100.1",
            ports=ports,
            dsts=None,
            conn_state="S0",
            spacing=30.0,
        )
        findings = run(_ctx(df, {"vertical_threshold": 15}))
        assert_report_voice(findings)
        scan_findings = [f for f in findings if f.evidence["scan_type"] == "vertical"]
        self.assertTrue(len(scan_findings) >= 1, "Expected at least one vertical finding")
        self.assertIn(scan_findings[0].severity, (Severity.HIGH, Severity.MEDIUM))

    def test_vertical_below_threshold_not_flagged(self) -> None:
        ports = list(range(1, 10))              # 9 ports < threshold 15
        df = _conn_df("192.0.2.1", "198.51.100.1",
                      ports=ports, dsts=None, conn_state="S0")
        findings = run(_ctx(df, {"vertical_threshold": 15}))
        vertical = [f for f in findings if f.evidence["scan_type"] == "vertical"]
        self.assertEqual(vertical, [])

    def test_vertical_evidence_uses_winning_window(self) -> None:
        base_ts = 1_748_563_200.0
        rows = [
            {
                "src": "192.0.2.1", "dst": "198.51.100.1", "port": 443,
                "proto": "tcp", "ts": base_ts + i * 20, "conn_state": "SF",
            }
            for i in range(10)
        ]
        rows.extend([
            {
                "src": "192.0.2.1", "dst": "198.51.100.1", "port": port,
                "proto": "tcp", "ts": base_ts + 1000 + i * 2, "conn_state": state,
            }
            for i, (port, state) in enumerate([
                (22, "S0"), (8080, "S0"), (55000, "SF"),
            ])
        ])
        rows.extend([
            {
                "src": "192.0.2.1", "dst": "198.51.100.1", "port": 443,
                "proto": "tcp", "ts": base_ts + 2000 + i * 20, "conn_state": "SF",
            }
            for i in range(10)
        ])

        result = _detect_vertical(
            _helper_frame(rows),
            {"vertical_threshold": 3, "window_secs": 10},
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["distinct_ports"], 3)
        self.assertEqual(result[0]["total_conns"], 3)
        self.assertEqual(result[0]["scan_state_ratio"], 0.667)
        self.assertEqual(result[0]["top_states"], "S0, SF")
        self.assertEqual(result[0]["port_range_entropy"], 1.099)
        self.assertEqual(result[0]["window_start"], "2025-05-30 00:16:40")

    def test_vertical_burst_only_result_stays_exact(self) -> None:
        base_ts = 1_748_563_200.0
        frame = _helper_frame([
            {
                "src": "192.0.2.1", "dst": "198.51.100.1", "port": port,
                "proto": "tcp", "ts": base_ts + i * 2, "conn_state": "S0",
            }
            for i, port in enumerate((22, 8080, 55000))
        ])

        self.assertEqual(
            _detect_vertical(frame, {"vertical_threshold": 3, "window_secs": 10}),
            [{
                "scan_type": "vertical",
                "src": "192.0.2.1",
                "dst": "198.51.100.1",
                "port": None,
                "port_class": None,
                "distinct_ports": 3,
                "distinct_hosts": 1,
                "total_conns": 3,
                "scan_state_ratio": 1.0,
                "top_states": "S0",
                "port_range_entropy": 1.099,
                "window_start": "2025-05-30 00:00:00",
                "window_secs": 10,
                "direction": "external→external",
            }],
        )

    # ── Horizontal scan ───────────────────────────────────────────────────────

    def test_horizontal_scan_detected(self) -> None:
        dsts = [f"198.51.100.{i}" for i in range(1, 31)]   # 30 distinct hosts
        df = _conn_df(
            src="192.0.2.1",
            dst=None,
            ports=[22],
            dsts=dsts,
            conn_state="REJ",
            spacing=10.0,
        )
        findings = run(_ctx(df, {"horizontal_threshold": 15}))
        horiz = [f for f in findings if f.evidence["scan_type"] == "horizontal"]
        self.assertTrue(len(horiz) >= 1, "Expected at least one horizontal finding")
        self.assertEqual(horiz[0].evidence["port"], 22)

    def test_horizontal_evidence_uses_winning_window(self) -> None:
        base_ts = 1_748_563_200.0
        rows = [
            {
                "src": "192.0.2.1", "dst": "198.51.100.99", "port": 22,
                "proto": "tcp", "ts": base_ts + i * 20, "conn_state": "SF",
            }
            for i in range(10)
        ]
        rows.extend([
            {
                "src": "192.0.2.1", "dst": dst, "port": 22,
                "proto": "tcp", "ts": base_ts + 1000 + i * 2, "conn_state": state,
            }
            for i, (dst, state) in enumerate([
                ("198.51.100.1", "REJ"),
                ("198.51.100.2", "REJ"),
                ("198.51.100.3", "SF"),
            ])
        ])
        rows.extend([
            {
                "src": "192.0.2.1", "dst": "198.51.100.99", "port": 22,
                "proto": "tcp", "ts": base_ts + 2000 + i * 20, "conn_state": "SF",
            }
            for i in range(10)
        ])

        result = _detect_horizontal(
            _helper_frame(rows),
            {"horizontal_threshold": 3, "window_secs": 10},
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["distinct_hosts"], 3)
        self.assertEqual(result[0]["total_conns"], 3)
        self.assertEqual(result[0]["scan_state_ratio"], 0.667)
        self.assertEqual(result[0]["top_states"], "REJ, SF")
        self.assertEqual(result[0]["velocity_hosts_per_sec"], 0.75)
        self.assertEqual(result[0]["window_start"], "2025-05-30 00:16:40")

    def test_horizontal_burst_only_result_stays_exact(self) -> None:
        base_ts = 1_748_563_200.0
        frame = _helper_frame([
            {
                "src": "192.0.2.1", "dst": f"198.51.100.{i + 1}", "port": 22,
                "proto": "tcp", "ts": base_ts + i * 2, "conn_state": "REJ",
            }
            for i in range(3)
        ])

        self.assertEqual(
            _detect_horizontal(frame, {"horizontal_threshold": 3, "window_secs": 10}),
            [{
                "scan_type": "horizontal",
                "src": "192.0.2.1",
                "dst": None,
                "port": 22,
                "port_class": "well-known",
                "distinct_ports": 1,
                "distinct_hosts": 3,
                "total_conns": 3,
                "scan_state_ratio": 1.0,
                "top_states": "REJ",
                "velocity_hosts_per_sec": 0.75,
                "window_start": "2025-05-30 00:00:00",
                "window_secs": 10,
                "direction": "external→external",
            }],
        )

    # ── Block scan ────────────────────────────────────────────────────────────

    def test_block_scan_detected(self) -> None:
        # 25 ports × 25 hosts, all S0 → scan_state_ratio = 1.0
        rows = []
        base_ts = 1_748_563_200.0
        for i, port in enumerate(range(1, 26)):
            for j, host_n in enumerate(range(1, 26)):
                rows.append({
                    "src"       : "192.0.2.1",
                    "dst"       : f"198.51.100.{host_n}",
                    "port"      : port,
                    "proto"     : "tcp",
                    "ts"        : base_ts + (i * 25 + j),
                    "conn_state": "S0",
                })
        df = pd.DataFrame(rows)
        findings = run(_ctx(df, {
            "block_port_threshold": 20,
            "block_host_threshold": 20,
            "block_state_min"     : 0.30,
        }))
        block = [f for f in findings if f.evidence["scan_type"] == "block"]
        self.assertTrue(len(block) >= 1, "Expected at least one block finding")

    # ── Slow scan ─────────────────────────────────────────────────────────────

    def test_slow_scan_detected(self) -> None:
        # 10 ports spread across 5 time buckets (one per bucket), all S0
        bucket_secs = 3600.0
        base_ts     = 1_748_563_200.0
        rows = []
        for bucket in range(5):
            for port in range(bucket * 2 + 1, bucket * 2 + 3):   # 2 ports per bucket
                rows.append({
                    "src"       : "192.0.2.1",
                    "dst"       : "198.51.100.1",
                    "port"      : port,
                    "proto"     : "tcp",
                    "ts"        : base_ts + bucket * bucket_secs + 60,
                    "conn_state": "S0",
                })
        df = pd.DataFrame(rows)
        findings = run(_ctx(df, {
            "slow_min_ports"   : 8,
            "slow_min_buckets" : 4,
            "slow_state_min"   : 0.30,
            "window_secs"      : int(bucket_secs),
            "vertical_threshold": 15,
        }))
        slow = [f for f in findings if f.evidence["scan_type"] == "slow"]
        self.assertTrue(len(slow) >= 1, "Expected at least one slow scan finding")

    def test_iot_discovery_tagged_by_destination_fraction(self) -> None:
        """A slow-scan-clearing src with IoT-ish top ports is tagged iot_discovery
        only when its DESTINATIONS are mostly internal; >10% non-internal
        destinations fall through to slow_scan.

        The iot fraction MUST key on dst_zone: the src is internal in BOTH cases,
        so src_zone is constant within the per-src group and cannot distinguish
        them - keying on src_zone would tag the >10%-external negative as
        iot_discovery too.
        """
        bucket_secs = 3600.0
        base_ts     = 1_748_563_200.0
        # 8 allowed ports: clears slow_min_ports=8 AND keeps is_iot's top-3 inside
        # IOT_DISCOVERY_PORTS | {53,443,80}. One port per bucket → 8 buckets.
        ports = [5353, 1900, 5355, 137, 138, 53, 443, 80]
        cfg = {"slow_min_ports": 8, "slow_min_buckets": 4, "slow_state_min": 0.30,
               "window_secs": int(bucket_secs), "vertical_threshold": 15}
        # 192.0.2.x internal; 198.51.100.x external (RFC 5737 doc space).
        home = ["192.0.2.0/24"]

        def _slow_rows(dsts: list[str]) -> pd.DataFrame:
            rows = []
            for i, (p, d) in enumerate(zip(ports, dsts)):
                rows.append({
                    "src": "192.0.2.10", "dst": d, "port": p, "proto": "udp",
                    "ts": base_ts + i * bucket_secs + 60, "conn_state": "S0",
                })
            return pd.DataFrame(rows)

        # POSITIVE: all destinations internal → iot_discovery.
        internal = _slow_rows(["192.0.2.20"] * 8)
        pos = [f for f in run(_ctx(internal, cfg, home_net=home))
               if f.evidence["scan_type"] == "slow"]
        self.assertTrue(pos, "expected a slow finding (positive)")
        self.assertEqual(pos[0].evidence["pattern_tag"], "iot_discovery")

        # NEGATIVE: 2 of 8 destinations external (>10%) → NOT iot (slow_scan).
        mixed = _slow_rows(["192.0.2.20"] * 6 + ["198.51.100.7"] * 2)
        neg = [f for f in run(_ctx(mixed, cfg, home_net=home))
               if f.evidence["scan_type"] == "slow"]
        self.assertTrue(neg, "expected a slow finding (negative)")
        self.assertNotEqual(neg[0].evidence["pattern_tag"], "iot_discovery")
        # dst_zone is an internal _prefilter column, never a finding-evidence field.
        self.assertNotIn("dst_zone", neg[0].evidence)

    # ── Finding construction ──────────────────────────────────────────────────

    def test_make_finding_vertical_title(self) -> None:
        # Title is flow/entity only - metrics belong in evidence, not title.
        row = _base_row("vertical")
        f   = _make_finding(row, _WINDOW)
        self.assertIn("192.0.2.1", f.title)
        self.assertIn("198.51.100.1", f.title)
        self.assertNotIn("ports", f.title)
        self.assertEqual(f.detector, "scan")
        self.assertEqual(f.severity, Severity.HIGH)
        # Metrics are in evidence
        self.assertIn("distinct_ports", f.evidence)

    def test_make_finding_horizontal_title(self) -> None:
        row = _base_row("horizontal")
        f   = _make_finding(row, _WINDOW)
        self.assertIn("*:22", f.title)
        self.assertNotIn("hosts", f.title)
        self.assertIn("distinct_hosts", f.evidence)

    def test_make_finding_block_title(self) -> None:
        row = _base_row("block")
        f   = _make_finding(row, _WINDOW)
        self.assertIn("→ *", f.title)
        self.assertNotIn("×", f.title)
        self.assertIn("distinct_ports", f.evidence)
        self.assertIn("distinct_hosts", f.evidence)

    def test_make_finding_slow_title(self) -> None:
        row = _base_row("slow")
        f   = _make_finding(row, _WINDOW)
        # Title is entity-only (the source) - the "slow scan" classification
        # is not in the title; render reconstructs it.
        self.assertEqual(f.title, f.evidence["src"])
        self.assertNotIn("slow scan", f.title)
        self.assertNotIn("windows", f.title)
        # Slow evidence includes temporal fields
        self.assertIn("temporal_spread_score", f.evidence)
        self.assertIn("active_buckets", f.evidence)

    def test_make_finding_evidence_fields_present(self) -> None:
        for scan_type in ("vertical", "horizontal", "block"):
            row = _base_row(scan_type)
            f   = _make_finding(row, _WINDOW)
            for field in ("scan_type", "src", "scan_state_ratio", "pattern_tag"):
                self.assertIn(field, f.evidence, f"Missing {field} in {scan_type} evidence")

    # ── Text renderer ─────────────────────────────────────────────────────────

    def test_text_renderer_scan_group(self) -> None:
        """Render a mixed set of scan findings; verify key tokens and no exceptions."""
        findings = [
            _make_finding(_base_row("vertical"),   _WINDOW),
            _make_finding(_base_row("horizontal"), _WINDOW),
        ]
        summary = RunSummary(
            data_window=_WINDOW,
            record_counts={"conn*.log*": 1000},
            data_size_bytes=0,
            detectors_run=["scan"],
            detectors_skipped={},
        )
        stream  = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=0)
        handler.begin(summary)
        handler.write(findings)
        handler.end()

        output = stream.getvalue()
        self.assertIn("ratio=", output)
        self.assertIn("ports",  output)
        self.assertIn("hosts",  output)
        self.assertIn("vertical",    output)
        self.assertIn("horizontal",  output)

    def test_text_renderer_verbose_scan_group(self) -> None:
        """Verbose mode emits description, evidence, and next steps."""
        finding = _make_finding(_base_row("vertical"), _WINDOW)
        summary = RunSummary(
            data_window=_WINDOW,
            record_counts={},
            data_size_bytes=0,
            detectors_run=["scan"],
            detectors_skipped={},
        )
        stream  = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=1)
        handler.begin(summary)
        handler.write([finding])
        handler.end()

        output = stream.getvalue()
        self.assertIn("evidence:",    output)
        self.assertIn("next steps:",  output)
        self.assertIn("data window:", output)


# ── Public-route window evidence regressions ─────────────────────────────────

def test_vertical_real_route_renders_winning_window_ratio_and_severity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    base_ts = 1_748_563_200.0
    src = "192.0.2.10"
    dst = "198.51.100.20"
    rows = [
        _zeek_conn(
            ts=base_ts + i * 300,
            src=src,
            dst=dst,
            port=443,
            state="SF",
        )
        for i in range(20)
    ]
    rows.extend([
        _zeek_conn(
            ts=base_ts + 10_000 + i * 2,
            src=src,
            dst=dst,
            port=1000 + i,
            state="S0",
        )
        for i in range(15)
    ])
    rows.extend([
        _zeek_conn(
            ts=base_ts + 20_000 + i * 300,
            src=src,
            dst=dst,
            port=443,
            state="SF",
        )
        for i in range(20)
    ])
    log_path = tmp_path / "conn.log"
    config_path = tmp_path / "config.toml"
    _write_conn_log(log_path, rows)
    _write_scan_config(config_path, vertical=15, horizontal=999)

    cli.main([
        "hunt",
        str(log_path),
        "--detect=scan",
        f"--config={config_path}",
        "--no-allowlist",
        "-q",
    ])

    output = capsys.readouterr().out
    rendered = [line for line in output.splitlines()
                if "vertical" in line and "ratio=" in line]
    assert len(rendered) == 1
    assert "[H]" in rendered[0]
    assert "ratio=1.00" in rendered[0]


def test_horizontal_real_route_renders_winning_window_ratio_and_severity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    base_ts = 1_748_563_200.0
    src = "192.0.2.10"
    rows = [
        _zeek_conn(
            ts=base_ts + i * 300,
            src=src,
            dst="198.51.100.99",
            port=22,
            state="SF",
        )
        for i in range(20)
    ]
    rows.extend([
        _zeek_conn(
            ts=base_ts + 10_000 + i * 2,
            src=src,
            dst=f"198.51.100.{i + 1}",
            port=22,
            state="REJ",
        )
        for i in range(15)
    ])
    rows.extend([
        _zeek_conn(
            ts=base_ts + 20_000 + i * 300,
            src=src,
            dst="198.51.100.99",
            port=22,
            state="SF",
        )
        for i in range(20)
    ])
    log_path = tmp_path / "conn.log"
    config_path = tmp_path / "config.toml"
    _write_conn_log(log_path, rows)
    _write_scan_config(config_path, vertical=999, horizontal=15)

    cli.main([
        "hunt",
        str(log_path),
        "--detect=scan",
        f"--config={config_path}",
        "--no-allowlist",
        "-q",
    ])

    output = capsys.readouterr().out
    rendered = [line for line in output.splitlines()
                if "horizontal" in line and "ratio=" in line]
    assert len(rendered) == 1
    assert "[H]" in rendered[0]
    assert "ratio=1.00" in rendered[0]


# ── Zone-label seam tests ─────────────────────────────────────────────────────
#
# Sample IPs use RFC 5737 documentation space throughout. Internal/external is
# defined by a test-specific home_net (e.g. 192.0.2.0/24) so 192.0.2.x reads
# as internal and 198.51.100.x / 203.0.113.x read as external - no RFC1918
# addresses appear in any traffic fixture.


def test_zone_of_returns_internal_for_home_net_ip() -> None:
    assert _zone_of("192.0.2.10", ["192.0.2.0/24"]) == "internal"


def test_zone_of_returns_external_for_outside_ip() -> None:
    assert _zone_of("198.51.100.10", ["192.0.2.0/24"]) == "external"


def test_zone_of_returns_external_for_unparseable_ip() -> None:
    assert _zone_of("not-an-ip", ["192.0.2.0/24"]) == "external"


def test_classify_direction_produces_four_byte_identical_strings() -> None:
    """Two-zone case MUST yield exactly the four direction strings.

    Proves the mechanical f-string rendering produces byte-identical
    direction-string output - so reports stay legible.
    """
    home_net = ["192.0.2.0/24"]
    cases = [
        # (src, dst, expected src_zone, expected dst_zone, expected rendered)
        ("192.0.2.5",   "192.0.2.6",    "internal", "internal", "internal→internal"),
        ("192.0.2.5",   "198.51.100.6", "internal", "external", "internal→external"),
        ("198.51.100.5","192.0.2.6",    "external", "internal", "external→internal"),
        ("198.51.100.5","203.0.113.6",  "external", "external", "external→external"),
    ]
    for src, dst, exp_src_zone, exp_dst_zone, exp_rendered in cases:
        src_zone, dst_zone, rendered = _classify_direction(src, dst, home_net)
        assert src_zone == exp_src_zone, (src, dst, src_zone)
        assert dst_zone == exp_dst_zone, (src, dst, dst_zone)
        assert rendered == exp_rendered, (src, dst, rendered)


def test_run_falls_back_to_default_home_net_when_context_empty() -> None:
    """Empty context.home_net activates scan's standalone-callable fallback.

    Traffic is doc-space only (no RFC1918). With the RFC1918 fallback in
    effect, every flow correctly classifies as ``external→external`` and
    the populated ``direction`` column makes its way into evidence - proving
    the fallback path activated and the column was populated, without
    smuggling private addresses into the fixture. (A future test needing to
    prove an internal-side classification through the empty-context path
    should monkeypatch _DEFAULT_HOME_NET to a doc-space range instead.)
    """
    src = "198.51.100.10"
    dsts = [f"203.0.113.{i}" for i in range(10, 35)]
    df = _conn_df(src, None, [22], dsts, conn_state="S0")
    ctx = DetectorContext(
        logs={"conn*.log*": df},
        config={},
        allowlist=None,
        data_window=_WINDOW,
        home_net=[],
    )
    findings = run(ctx)
    assert findings, "fallback should keep run() functional with empty context.home_net"
    for f in findings:
        assert f.evidence.get("direction") == "external→external", (
            "RFC1918 fallback should classify doc-space src→doc-space dst as external→external"
        )


if __name__ == "__main__":
    unittest.main()
