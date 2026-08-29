"""Regressions for config-falsifiable detector descriptions.

Each F01-F15 test drives the detector's public ``run()`` path at the config
boundary that made the old prose false.  Fixtures are self-contained and use
documentation addresses and placeholder identities.
"""

from __future__ import annotations

from datetime import datetime, timezone
import html
import io
import re

import pandas as pd

from sigwood.common.finding import DetectorContext, RunSummary, Severity
from sigwood.detectors import aws, beacon, dns, exfil, scan, syslog
from sigwood.outputs.html import render_report_html
from sigwood.outputs.text import TextHandler


_BASE = 1_786_000_000.0
_WINDOW = (
    datetime.fromtimestamp(_BASE, timezone.utc),
    datetime.fromtimestamp(_BASE + 14 * 86_400, timezone.utc),
)

_BANNED_READER_VOCABULARY = (
    "configured",
    "threshold",
    "floor",
    "minimum",
    "standardized",
    "spectral share",
    "prominence",
    "scored by entropy",
)


def _assert_plain(description: str) -> None:
    """Check only an F01-F15 public-run description, never source literals."""
    lowered = description.casefold()
    assert all(
        re.search(rf"\b{re.escape(word)}\b", lowered) is None
        for word in _BANNED_READER_VOCABULARY
    )


def _context(
    pattern: str,
    frame: pd.DataFrame,
    config: dict,
    *,
    home_net: tuple[str, ...] = (),
) -> DetectorContext:
    return DetectorContext.unsuppressed(
        {pattern: frame},
        data_window=(
            datetime.fromtimestamp(float(frame["ts"].min()), timezone.utc),
            datetime.fromtimestamp(float(frame["ts"].max()), timezone.utc),
        ),
        config=config,
        home_net=home_net,
    )


def _aws_event(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "ts": _BASE,
        "principal": "placeholder-role/session",
        "lane": "interactive",
        "read_write": "read",
        "event_source": "s3.amazonaws.com",
        "event_name": "GetObject",
        "identity_type": "AssumedRole",
        "source_ip": "192.0.2.10",
        "error_code": None,
        "aws_region": "us-east-1",
        "event_id": "10000000-0000-0000-0000-000000000000",
        "raw": {},
    }
    row.update(overrides)
    return row


def _aws_burst(rows: list[dict[str, object]], config: dict) -> object:
    frame = pd.DataFrame(rows)
    findings = aws.run(_context("*.json*", frame, config))
    return next(finding for finding in findings if finding.evidence.get("tier") == "burst")


def test_f01_aws_service_count_does_not_print_multiple_services() -> None:
    rows = [
        _aws_event(
            ts=_BASE + index,
            event_name=action,
            event_id=f"10000000-0000-0000-0000-{index:012d}",
        )
        for index, action in enumerate(("GetObject", "ListBuckets", "HeadObject", "PutObject"))
    ]
    finding = _aws_burst(rows, {"burst_gap_seconds": 300, "burst_min_firsts": 3})

    assert finding.evidence["new_service_count"] == 1
    assert "across multiple services" not in finding.description
    assert "A group of first-seen actions for this principal." in finding.description
    _assert_plain(finding.description)


def test_f02_aws_config_scaled_span_does_not_print_short_window() -> None:
    rows = [
        _aws_event(
            ts=_BASE + offset,
            event_source=f"{service}.amazonaws.com",
            event_name=f"Describe{service.upper()}",
            event_id=f"20000000-0000-0000-0000-{index:012d}",
        )
        for index, (service, offset) in enumerate(
            (("s3", 0), ("iam", 1), ("ec2", 5 * 86_400 + 1), ("lambda", 10 * 86_400 + 1))
        )
    ]
    finding = _aws_burst(
        rows, {"burst_gap_seconds": 14 * 86_400, "burst_min_firsts": 3}
    )

    assert finding.evidence["span_seconds"] == 10 * 86_400
    assert "short window" not in finding.description
    assert "The pattern may reflect enumeration or recon" in finding.description
    _assert_plain(finding.description)


def _aws_ranked(config: dict, rows: list[dict[str, object]]) -> list[object]:
    frame = pd.DataFrame(rows)
    return [
        finding
        for finding in aws.run(_context("*.json*", frame, config))
        if finding.evidence.get("tier") == "ranked"
    ]


def test_f03_aws_composite_names_signed_sum_at_zero_and_negative() -> None:
    zero_rows = [
        _aws_event(
            principal=f"placeholder-role-{principal}/session",
            ts=_BASE + event,
            event_id=f"30000000-0000-{principal:04d}-0000-{event:012d}",
        )
        for principal in range(5)
        for event in range(2)
    ]
    zero = _aws_ranked(
        {
            "min_events": 1,
            "min_scorable_principals": 1,
            "burst_min_firsts": 99,
            "composite_medium_threshold": 1.0,
            "composite_low_threshold": -1.0,
        },
        zero_rows,
    )
    assert zero and all(finding.evidence["composite_z"] == 0.0 for finding in zero)

    varied_rows: list[dict[str, object]] = []
    for principal in range(5):
        for event in range(2):
            high = principal != 0
            varied_rows.append(
                _aws_event(
                    principal=f"placeholder-varied-{principal}/session",
                    ts=_BASE + event,
                    event_name=f"Action{event}" if high else "GetObject",
                    source_ip=f"192.0.2.{20 + event}" if high else "192.0.2.10",
                    error_code="AccessDenied" if high and event == 0 else None,
                    event_id=f"40000000-0000-{principal:04d}-0000-{event:012d}",
                )
            )
    varied = _aws_ranked(
        {
            "min_events": 1,
            "min_scorable_principals": 1,
            "burst_min_firsts": 99,
            "composite_medium_threshold": 99.0,
            "composite_low_threshold": -99.0,
        },
        varied_rows,
    )
    negative = next(finding for finding in varied if finding.evidence["composite_z"] < 0)

    for finding in [zero[0], negative]:
        assert "unusual for the population" not in finding.description
        assert finding.description.startswith("Composite score ")
        assert "compare within this window's principal population" in finding.description
        _assert_plain(finding.description)


def test_f04_beacon_low_threshold_prints_measured_fft_terms() -> None:
    increments = [47, 311, 83, 719, 131, 503, 61, 947, 179, 389] * 3
    timestamps = [_BASE]
    for increment in increments:
        timestamps.append(timestamps[-1] + increment)
    frame = pd.DataFrame(
        [
            {
                "ts": timestamp,
                "src": "192.0.2.10",
                "dst": "198.51.100.20",
                "port": 443,
                "proto": "tcp",
                "conn_state": "SF",
                "bytes": 100,
                "local_orig": True,
            }
            for timestamp in timestamps
        ]
    )
    finding = beacon.run(
        _context(
            "conn*.log*",
            frame,
            {"threshold": 0.000001, "min_connections": 10},
            home_net=("192.0.2.0/24",),
        )
    )[0]

    assert "near-fixed" not in finding.description
    assert "regular cadence" not in finding.description
    assert finding.description.startswith("The strongest repeating interval")
    assert ". " not in finding.description
    _assert_plain(finding.description)
    assert finding.next_steps[0] == "Identify the process on 192.0.2.10 behind these connections"


def _dns_below_gate() -> object:
    frame = pd.DataFrame(
        [
            {
                "ts": _BASE + index,
                "src": "192.0.2.10",
                "query": "only.family.example",
                "rcode": 3 if index < 2 else 0,
                "rtt": 0.05,
                "ttl": 30.0,
                "answer": [],
                "tc": False,
            }
            for index in range(100)
        ]
    )
    config = dict(dns.DEFAULT_CONFIG)
    config.update(
        {
            "min_cluster_size": 2000,
            "min_samples": 100,
            "threshold": 999.0,
            "thresh_high_entropy": 999.0,
            "promote_below_gate": True,
            "promote_min_subdomains": 1,
            "promote_min_nxdomain_fraction": 0.01,
            "scan_dense_clusters": False,
        }
    )
    findings = dns.run(_context("dns*.log*", frame, config))
    return next(
        finding for finding in findings if finding.evidence.get("tier") == "below_gate_group"
    )


def test_f05_dns_single_name_does_not_print_family() -> None:
    finding = _dns_below_gate()

    assert finding.evidence["subdomain_count"] == 1
    assert "family of names" not in finding.description
    assert finding.description.startswith(
        "1 distinct name under private namespace example"
    )
    _assert_plain(finding.description)


def test_f06_dns_low_failure_fraction_does_not_print_mostly() -> None:
    finding = _dns_below_gate()

    assert finding.evidence["nxdomain_fraction"] == 0.02
    assert "mostly fail" not in finding.description
    assert "failed to resolve in 2% of lookups" in finding.description
    _assert_plain(finding.description)


def _exfil_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "ts": _BASE,
        "src": "192.0.2.10",
        "dst": "198.51.100.20",
        "bytes": 1,
        "resp_bytes": 99,
        "port": 443,
        "proto": "tcp",
        "duration": 1.0,
        "local_orig": True,
    }
    row.update(overrides)
    return row


def _exfil_findings(rows: list[dict[str, object]]) -> list[object]:
    frame = pd.DataFrame(rows)
    return exfil.run(
        _context(
            "conn*.log*",
            frame,
            {"min_outbound_bytes": 1, "min_orig_share": 0.01},
            home_net=("192.0.2.0/24",),
        )
    )


def test_f07_exfil_pair_uses_inclusive_configured_floors() -> None:
    finding = _exfil_findings([_exfil_row()])[0]

    assert finding.evidence["orig_bytes_total"] == 1
    assert finding.evidence["orig_share"] == 0.01
    assert "originator-dominant" not in finding.description
    assert "bulk data transfer" not in finding.description
    assert finding.description == (
        "This host sent data out to a destination outside your network. The figures "
        "cover only connections where both byte counts were recorded."
    )
    _assert_plain(finding.description)


def test_f08_exfil_pool_uses_inclusive_configured_floors() -> None:
    finding = _exfil_findings(
        [_exfil_row(dst=f"198.51.100.{host}") for host in (20, 21, 22, 23)]
    )[0]

    assert finding.evidence["tier"] == "destination_pool"
    assert all(member["orig_share"] == 0.01 for member in finding.evidence["members"])
    assert "originator-dominant" not in finding.description
    assert "bulk data transfer" not in finding.description
    assert finding.description == (
        "This host sent data out to a group of destinations outside your network. "
        "The figures cover only connections where both byte counts were recorded."
    )
    _assert_plain(finding.description)


def _scan_context(frame: pd.DataFrame, config: dict) -> DetectorContext:
    return _context(
        "conn*.log*", frame, config, home_net=("192.0.2.0/24",)
    )


def test_f09_scan_one_connection_does_not_print_repeated_attempts() -> None:
    frame = pd.DataFrame(
        [
            {
                "ts": _BASE,
                "src": "192.0.2.10",
                "dst": "198.51.100.20",
                "port": 443,
                "proto": "tcp",
                "conn_state": "SF",
            }
        ]
    )
    config = dict(scan.DEFAULT_CONFIG)
    config.update(
        {
            "vertical_threshold": 1,
            "horizontal_threshold": 2,
            "block_port_threshold": 2,
            "block_host_threshold": 2,
            "slow_min_ports": 99,
        }
    )
    finding = next(
        finding
        for finding in scan.run(_scan_context(frame, config))
        if finding.evidence.get("scan_type") == "vertical"
    )

    assert finding.evidence["total_conns"] == 1
    assert "repeated connection attempts" not in finding.description
    assert "across 1 connection attempt" in finding.description
    _assert_plain(finding.description)

    plural_frame = pd.concat(
        [frame, frame.assign(ts=_BASE + 1, port=444)], ignore_index=True
    )
    plural_finding = next(
        item
        for item in scan.run(_scan_context(plural_frame, config))
        if item.evidence.get("scan_type") == "vertical"
    )
    assert plural_finding.evidence["total_conns"] == 2
    assert "across 2 connection attempts" in plural_finding.description
    _assert_plain(plural_finding.description)


def test_f09_scan_missing_count_defensive_arm_omits_none() -> None:
    finding = scan._make_finding(
        {
            "scan_type": "vertical",
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "port": None,
            "pattern_notes": "",
            "pattern_tag": "unknown",
            "scan_state_ratio": 0.0,
            "_severity": Severity.LOW,
        },
        _WINDOW,
    )

    assert finding.description == (
        "A vertical scan pattern consistent with port or host enumeration."
    )
    assert "None" not in finding.description


def test_f10_scan_one_window_does_not_print_several_or_moderate() -> None:
    frame = pd.DataFrame(
        [
            {
                "ts": _BASE,
                "src": "192.0.2.10",
                "dst": "198.51.100.20",
                "port": 443,
                "proto": "tcp",
                "conn_state": "SF",
            }
        ]
    )
    config = dict(scan.DEFAULT_CONFIG)
    config.update(
        {
            "vertical_threshold": 99,
            "horizontal_threshold": 99,
            "block_port_threshold": 99,
            "block_host_threshold": 99,
            "slow_state_min": 0.0,
            "slow_min_ports": 1,
            "slow_min_buckets": 1,
        }
    )
    finding = next(
        finding
        for finding in scan.run(_scan_context(frame, config))
        if finding.evidence.get("pattern_tag") == "slow_scan_candidate"
    )

    assert finding.evidence["active_buckets"] == 1
    assert "several time windows" not in finding.description
    assert "moderate scan-indicative" not in finding.description
    assert "across 1 time window" in finding.description
    _assert_plain(finding.description)

    plural_frame = pd.concat(
        [frame, frame.assign(ts=_BASE + config["window_secs"], port=444)],
        ignore_index=True,
    )
    plural_finding = next(
        item
        for item in scan.run(_scan_context(plural_frame, config))
        if item.evidence.get("pattern_tag") == "slow_scan_candidate"
    )
    assert plural_finding.evidence["active_buckets"] == 2
    assert "across 2 time windows" in plural_finding.description
    _assert_plain(plural_finding.description)


def _slow_scan(
    window_secs: int,
    *,
    bucket_count: int = 4,
    connections_per_bucket: int = 3,
) -> object:
    ports = [1080, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 27017, 4444, 5555]
    rows = []
    for bucket in range(bucket_count):
        for index in range(connections_per_bucket):
            rows.append(
                {
                    "ts": _BASE + bucket * window_secs + index * 0.1,
                    "src": "192.0.2.10",
                    "dst": f"198.51.100.{20 + index}",
                    "port": ports[bucket * connections_per_bucket + index],
                    "proto": "tcp",
                    "conn_state": "S0",
                }
            )
    frame = pd.DataFrame(rows)
    config = dict(scan.DEFAULT_CONFIG)
    config["window_secs"] = window_secs
    config["slow_min_buckets"] = min(bucket_count, config["slow_min_buckets"])
    return next(
        finding
        for finding in scan.run(_scan_context(frame, config))
        if finding.evidence.get("scan_type") == "slow"
    )


def test_f11_scan_slow_names_observed_windows_without_intent() -> None:
    one_second = _slow_scan(1)
    one_hour = _slow_scan(3600)
    singular = _slow_scan(1, bucket_count=1, connections_per_bucket=8)

    for finding in (one_second, one_hour):
        assert "deliberately slow" not in finding.description
        assert "paced to avoid" not in finding.description
        assert (
            "with no single window reaching the 15 ports that would surface it as "
            "an ordinary scan"
        ) in finding.description
        _assert_plain(finding.description)
    assert "across 4 time windows of 1s each" in one_second.description
    assert "across 4 time windows of 1h each" in one_hour.description
    assert "across 1 time window of 1s each" in singular.description


def _syslog_frame(*, reboot: bool = False) -> pd.DataFrame:
    rows = [
        {
            "ts": _BASE + index,
            "host": "placeholder-host",
            "program": "cron",
            "raw": f"cron[{index}]: routine session opened",
            "message": "cron[*]: routine session opened",
        }
        for index in range(60)
    ]
    rows.extend(
        {
            "ts": _BASE + 100 + index,
            "host": "placeholder-host",
            "program": "other",
            "raw": f"other: distinct event {index}",
            "message": f"other: distinct word-{chr(97 + index)}",
        }
        for index in range(4)
    )
    if reboot:
        rows.append(
            {
                "ts": _BASE + 101,
                "host": "placeholder-host",
                "program": "systemd-logind",
                "raw": "systemd-logind[1]: System is rebooting.",
                "message": "systemd-logind: System is rebooting.",
            }
        )
    return pd.DataFrame(rows)


def _syslog_findings(config: dict, *, reboot: bool = False) -> list[object]:
    frame = _syslog_frame(reboot=reboot)
    merged = dict(syslog.DEFAULT_CONFIG)
    merged.update(config)
    return syslog.run(_context("*.log*", frame, merged))


def test_f12_syslog_burst_defines_template_frequency() -> None:
    finding = next(
        finding
        for finding in _syslog_findings(
            {
                "rarity_pct": 100,
                "max_count": 100,
                "burst_gap_seconds": 60,
                "burst_min_size": 4,
                "recognize_transactions": False,
            }
        )
        if finding.evidence.get("tier") == "burst"
    )

    assert "cluster of rare log lines" not in finding.description
    assert "short window" not in finding.description
    assert "each from a pattern that appeared at most 100 times in this run" in finding.description
    _assert_plain(finding.description)


def test_f13_syslog_rebooted_burst_keeps_template_frequency_object() -> None:
    finding = next(
        finding
        for finding in _syslog_findings(
            {
                "rarity_pct": 100,
                "max_count": 100,
                "burst_gap_seconds": 60,
                "burst_min_size": 4,
                "recognize_transactions": False,
            },
            reboot=True,
        )
        if finding.evidence.get("tier") == "burst"
        and finding.evidence.get("label") == "rebooted"
    )

    assert "cluster of rare log lines" not in finding.description
    assert "short window" not in finding.description
    assert "each from a pattern that appeared at most 100 times in this run" in finding.description
    assert finding.description.endswith("coinciding with a reboot of this host.")
    _assert_plain(finding.description)


def test_f14_syslog_family_defines_template_frequency() -> None:
    finding = next(
        finding
        for finding in _syslog_findings(
            {
                "rarity_pct": 100,
                "max_count": 100,
                "burst_min_size": 100,
                "family_min_size": 4,
                "recognize_transactions": False,
            }
        )
        if finding.evidence.get("tier") == "family"
        and finding.evidence.get("program") == "cron"
    )

    assert finding.evidence["line_count"] == 60
    assert "set of rare log lines" not in finding.description
    assert "each from a pattern that appeared at most 100 times in this run" in finding.description
    _assert_plain(finding.description)


def test_f15_syslog_needle_defines_template_frequency() -> None:
    finding = next(
        finding
        for finding in _syslog_findings(
            {
                "rarity_pct": 100,
                "max_count": 100,
                "burst_min_size": 100,
                "family_min_size": 100,
                "recognize_transactions": False,
            }
        )
        if finding.evidence.get("program") == "cron"
    )

    assert "Rare log template observed" not in finding.description
    assert finding.description.startswith("This log pattern appeared at most 100 times in this run.")
    _assert_plain(finding.description)


def test_representative_narrowings_reach_verbose_text_and_html() -> None:
    aws_finding = _aws_burst(
        [
            _aws_event(
                ts=_BASE + index,
                event_name=action,
                event_id=f"50000000-0000-0000-0000-{index:012d}",
            )
            for index, action in enumerate(
                ("GetObject", "ListBuckets", "HeadObject", "PutObject")
            )
        ],
        {"burst_gap_seconds": 300, "burst_min_firsts": 3},
    )

    timestamps = [_BASE]
    for increment in [47, 311, 83, 719, 131, 503, 61, 947, 179, 389] * 3:
        timestamps.append(timestamps[-1] + increment)
    beacon_frame = pd.DataFrame(
        [
            {
                "ts": timestamp,
                "src": "192.0.2.10",
                "dst": "198.51.100.20",
                "port": 443,
                "proto": "tcp",
                "conn_state": "SF",
                "bytes": 100,
                "local_orig": True,
            }
            for timestamp in timestamps
        ]
    )
    beacon_finding = beacon.run(
        _context(
            "conn*.log*",
            beacon_frame,
            {"threshold": 0.000001, "min_connections": 10},
            home_net=("192.0.2.0/24",),
        )
    )[0]

    findings = [
        aws_finding,
        beacon_finding,
        _dns_below_gate(),
        _exfil_findings([_exfil_row()])[0],
        _slow_scan(1),
        next(
            finding
            for finding in _syslog_findings(
                {
                    "rarity_pct": 100,
                    "max_count": 100,
                    "burst_min_size": 100,
                    "family_min_size": 4,
                    "recognize_transactions": False,
                }
            )
            if finding.evidence.get("tier") == "family"
            and finding.evidence.get("program") == "cron"
        ),
    ]
    detector_names = [finding.detector for finding in findings]
    summary = RunSummary(
        data_window=_WINDOW,
        record_counts={"probe": len(findings)},
        data_size_bytes=0,
        detectors_run=detector_names,
        detectors_skipped={},
        detector_missions={name: f"Mission for {name}." for name in detector_names},
        generated_at=datetime(2026, 8, 29, tzinfo=timezone.utc),
    )

    stream = io.StringIO()
    text_handler = TextHandler(stream=stream, verbose_level=1)
    text_handler.begin(summary)
    text_handler.write(findings)
    text_handler.end()
    text_output = stream.getvalue()
    html_output = render_report_html(
        findings, summary, verbose_level=1, max_findings_per_detector=100
    )

    for finding in findings:
        assert finding.description in text_output
        assert html.escape(finding.description) in html_output
