"""Synthetic report cases for browser and PDF layout checks.

Run with ``PYTHONPATH=. python tests/html_layout_cases.py OUTPUT_DIR``. Expected
address identities are fixture data, independent of the projection metadata.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.outputs.html import render_report_html

IP4 = "192.0.2.222"
PEER4 = "198.51.100.222"
IP6 = "2001:0db8:1234:5678:90ab:cdef:1234:5678"
PEER6 = "2001:0db8:abcd:ef01:2345:6789:abcd:ef01"
DOMAIN = ".".join(("longlabel" * 3, "otherlabel" * 3, "example", "org"))
PRINCIPAL = "arn:aws:iam::123456789012:role/team.example/" + "service." * 8
LONG_PRINCIPAL = "p" * 120
LONG_ACCOUNT = "account" * 20
LONG_TITLE = "entity" * 24
START = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
END = datetime(2026, 6, 1, 18, tzinfo=timezone.utc)


@dataclass(frozen=True)
class LayoutCase:
    name: str
    finding: Finding
    # Indexed by the existing projection columns, not discovered from new flags.
    addresses: tuple[tuple[int, tuple[str, ...]], ...] = ()
    nowrap_columns: tuple[int, ...] = ()


def layout_cases() -> list[LayoutCase]:
    cases = []

    def add(name, detector, title, evidence, addresses=(), nowrap=()):
        cases.append(LayoutCase(name, Finding(
            detector=detector, severity=Severity.MEDIUM, title=title,
            description="Review the recorded activity.", evidence=evidence,
            next_steps=["Inspect the source records."], ts_generated=END,
            data_window=(START, END),
        ), addresses, nowrap))

    for label, src, dst in (("ipv4", IP4, PEER4), ("ipv6", IP6, PEER6)):
        add("beacon-" + label, "beacon", f"{src} -> {dst}:443/tcp", {
            "src_ip": src, "dst_ip": dst, "dst_port": 443, "proto": "tcp",
            "period_str": "61.5m", "beacon_score": .93, "conn_count": 147,
            "first_seen": START, "peers": [src, dst],
        }, ((0, (src,)), (2, (dst,))), (0, 1, 2))
    add("ssl-ipv6", "ssl", f"{IP6} -> {PEER6}", {
        "src": IP6, "dst": PEER6, "conn_count": 29,
        "tls_versions": {"TLSv13": 29}, "first_seen": START,
        "severity_basis": ["sni_absent", "validation"],
        "validation_status": "self signed certificate in certificate chain",
    }, ((0, (IP6,)), (2, (PEER6,))), (0, 1, 2))
    for tier, dst in (("single", PEER4), ("destination_pool", "2001:db8:abcd::/48")):
        add("exfil-" + tier, "exfil", f"{IP6} -> {dst}", {
            "src": IP6, "dst": dst, "destination_network": dst, "tier": tier,
            "destination_count": 8, "connection_count": 120,
            "orig_bytes_total": 1200000, "orig_share": .95,
            "span_seconds": 86400, "services": ["ssl"],
        }, ((0, (IP6,)), (2, (dst,))), (0, 1, 2))
    for shape in ("vertical", "horizontal", "block", "slow"):
        add("scan-" + shape, "scan", f"{IP6} -> {PEER6}", {
            "src": IP6, "dst": PEER6, "scan_type": shape, "port": 443,
            "distinct_ports": 42, "distinct_hosts": 12, "active_buckets": 7,
            "scan_state_ratio": .96,
        }, ((0, (IP6,)),) + (((1, (PEER6,)),) if shape == "vertical" else ()), (0,))
    add("scan-rollup", "scan", f"{IP6} -> *", {
        "src": IP6, "tier": "rollup", "scan_type": "vertical",
        "target_count": 12, "max_scan_state_ratio": .97,
    }, ((0, (IP6,)),), (0,))
    for kind in ("arrival", "burst", "arrival_fold"):
        title = IP6 if kind == "arrival_fold" else f"{IP6} → {DOMAIN}"
        add("dnsblock-" + kind, "dnsblock", title, {
            "kind": kind, "address": IP6, "family_key": DOMAIN,
            "coverage_lane": "strong", "active_periods": 3,
            "eligible_periods": 21, "attributed_query_count": 1200,
            "qualifying_name_count": 6, "prior_other_address_count": 2,
            "first_associated_period": "2026-06-01",
            "earliest_first_associated_period": "2026-06-01",
            "history_seconds": 1814400, "peak_count": 500,
            "baseline_median_twice": 20, "member_count": 3,
        }, ((0, (IP6,)),), (0,) if kind == "arrival_fold" else ())
    for kind in ("unlabeled", "mismatch"):
        add("protocol-" + kind, "protocol", f"{IP6} -> {PEER6}:8443/tcp", {
            "kind": kind, "src": IP6, "dst": PEER6,
            "services": ["ssl"], "mismatched_services": ["ssl"],
            "expected_ports": {"ssl": [443]}, "conventional_ports": {},
            "eligible_unlabeled_conns": 31, "conns": 45,
            "norm_class": "registered", "first_seen": START.isoformat(),
        }, ((0, (IP6, PEER6)),), (0,))
    add("protocol-rollup", "protocol", "ssl on 8443/tcp", {
        "kind": "rollup", "member_count": 21,
    })
    for name, title, signal, source in (
        ("account", "example-account", "account_volume", IP4),
        ("long-account", LONG_ACCOUNT, "account_volume", IP4),
        ("source", IP6, "source_volume", IP6),
        ("host", "host.example.org · ssh", "host_spread", None),
        ("neutral", "high-volume authentication failures", "concentration", None),
        ("landing", IP4, "landing", IP4),
    ):
        evidence = dict(signal=signal, decision_record_count=50, denial_count=42,
                        host_count=3, span_seconds=120)
        if source:
            evidence["source"] = source
        add("auth-" + name, "auth", title, evidence,
            ((0, (source,)),) if title == source else (), (0,))
    add("dns-singleton", "dns", DOMAIN, {
        "label_score": 4.5, "query_count": 143, "unique_sources": 3,
    })
    add("dns-group", "dns", DOMAIN, {
        "subdomain_count": 42, "max_label_score": 4.9, "min_label_score": 4.2,
        "total_queries": 234, "unique_sources": 4, "registrable_domain": DOMAIN,
    })
    for tier in ("burst", "ranked"):
        for name, principal in (("separators", PRINCIPAL), ("unbroken", LONG_PRINCIPAL)):
            add("aws-" + tier + "-" + name, "aws", principal, {
                "tier": tier, "principal": principal, "new_action_count": 42,
                "new_service_count": 5, "span_seconds": 7200,
                "error_rate": .2, "composite_z": 3.5, "event_count": 123,
                "distinct_source_ip": 4,
            })
    add("generic", "custom", LONG_TITLE, {"src": IP6})
    add("syslog-needle", "syslog", "Jun  1 12:01:00 host.example app: " + "sample " * 35, {})
    add("syslog-family", "syslog", "repeated event sample", {
        "tier": "family", "first_seen": START, "last_seen": END,
        "start_ts": START.timestamp(), "line_count": 42, "program": "service",
        "template": "service <*> restarted", "hosts": ["host.example.org"],
    })
    return cases


def layout_summary() -> RunSummary:
    detectors = list(dict.fromkeys(case.finding.detector for case in layout_cases()))
    return RunSummary(data_window=(START, END), record_counts={"conn.log": 2000},
                      data_size_bytes=240000, detectors_run=detectors, detectors_skipped={})


def write_reports(directory: Path, *, pdf: bool = False) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    cases = layout_cases()
    findings = [case.finding for case in cases]
    summary = layout_summary()
    expected = [dict(name=c.name, detector=c.finding.detector, title=c.finding.title,
                     addresses=c.addresses, nowrap_columns=c.nowrap_columns) for c in cases]
    (directory / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    for level in range(3):
        (directory / f"layout-{level}.html").write_text(render_report_html(
            findings, summary, verbose_level=level))
        if pdf:
            from sigwood.outputs.pdf import PdfHandler
            handler = PdfHandler(output_path=directory / f"layout-{level}.pdf", verbose_level=level)
            handler.begin(summary)
            handler.write(findings)
            handler.end()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--pdf", action="store_true")
    args = parser.parse_args()
    write_reports(args.directory, pdf=args.pdf)
