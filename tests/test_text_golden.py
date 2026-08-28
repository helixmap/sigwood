"""Byte-output golden pins for the text reading surface, per detector/variant.

GOLDEN SAFETY NET: these pin the EXACT text output for the text reading surface.
The render pipeline + cell projection live in ``outputs/_render_model.py``; every
assertion below is byte-exact; deliberate output changes are reviewed line by line. RFC 5737 fixtures;
sentinel-ish values.

Timestamps are pinned to UTC by the conftest session fixture, so the verbose
``data window`` line is deterministic.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.outputs.text import TextHandler

RULE = "─" * 80
_W = (
    datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
    datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
)


def _f(detector, severity, title, evidence, *, description="", next_steps=None):
    return Finding(
        detector=detector, severity=severity, title=title, description=description,
        evidence=evidence, next_steps=next_steps or [],
        ts_generated=_W[1], data_window=_W,
    )


def _render(findings, *, level=0, cap=100):
    buf = io.StringIO()
    names = list(dict.fromkeys(finding.detector for finding in findings))
    summary = RunSummary(
        data_window=_W,
        record_counts={},
        data_size_bytes=0,
        detectors_run=names,
        detectors_skipped={},
        detector_missions={name: f"Mission for {name}." for name in names},
    )
    handler = TextHandler(
        stream=buf, verbose_level=level, max_findings_per_detector=cap,
    )
    handler.begin(summary)
    buf.seek(0)
    buf.truncate(0)
    handler.write(findings)
    return buf.getvalue()


# ── beacon ───────────────────────────────────────────────────────────────────
def test_golden_beacon():
    out = _render([_f("beacon", Severity.MEDIUM, "192.0.2.10 → 198.51.100.20:443/tcp",
        {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": 443,
         "proto": "tcp", "period_str": "60.0m", "beacon_score": 0.6083,
         "conn_count": 918273})])
    assert out == (
        f"\nbeacon - 1 finding · 1 medium\nMission for beacon.\n{RULE}\n"
        "medium  192.0.2.10  →  198.51.100.20:443/tcp   period=60.0m   rhythm=0.608   918,273 conns\n\n"
    )


# ── dns: singleton (blocked column vanishes / appears) + group ───────────────
def test_golden_dns_singleton_no_blocked_column():
    out = _render([_f("dns", Severity.MEDIUM, "weirddomain.example",
        {"source": "zeek", "label_score": 4.7771, "query_count": 531, "unique_sources": 7})])
    assert out == (
        f"\ndns - 1 finding · 1 medium\nMission for dns.\n{RULE}\n"
        "singletons (1)\n"
        "  medium  generated-look=4.78  queries=531  clients=7  weirddomain.example\n\n"
    )


def test_golden_dns_singleton_blocked_column_present():
    out = _render([_f("dns", Severity.HIGH, "blockeddomain.example",
        {"source": "pihole", "label_score": 4.9112, "query_count": 612,
         "unique_sources": 3, "was_blocked": True, "block_ratio": 0.5})])
    assert out == (
        f"\ndns - 1 finding · 1 high\nMission for dns.\n{RULE}\n"
        "singletons (1)\n"
        "  high    generated-look=4.91  queries=612  clients=3  BLOCKED  blockeddomain.example\n\n"
    )


def test_golden_dns_group():
    out = _render([_f("dns", Severity.MEDIUM, "example.net",
        {"source": "zeek", "registrable_domain": "example.net", "subdomain_count": 42,
         "max_label_score": 4.9001, "min_label_score": 3.1002, "total_queries": 8123,
         "unique_sources": 9})])
    assert out == (
        f"\ndns - 1 finding · 1 medium\nMission for dns.\n{RULE}\n"
        "groups (1)\n"
        "  medium  names=42  generated-look=4.90-3.10  queries=8123  clients=9  example.net\n\n"
    )


def test_golden_dns_dense_cluster_scan_summary():
    # A dense-origin group + the synthetic scan_summary (its own trailing
    # full-width section; counts in the group header like aws ranked_summary).
    out = _render([
        _f("dns", Severity.HIGH, "tunnel.example",
           {"source": "zeek", "origin": "dense_cluster", "registrable_domain": "tunnel.example",
            "subdomain_count": 600, "max_label_score": 2.1900, "min_label_score": 1.9700,
            "total_queries": 600, "unique_sources": 1,
            "sample_domains": ["a.tunnel.example"], "querier_ips": ["192.0.2.10"]}),
        _f("dns", Severity.INFO, "dense-cluster scan: high-entropy clusters surfaced",
           {"tier": "scan_summary", "cluster_count": 1, "total_members": 600,
            "registrable_domains": ["tunnel.example"]}),
    ])
    assert out == (
        f"\ndns - 2 findings · 1 high  1 info\nMission for dns.\n{RULE}\n"
        "groups (1)\n"
        "  high    names=600  generated-look=2.19-1.97  queries=600  clients=1  tunnel.example\n\n"
        "dense-cluster scan (1)\n"
        "  info    dense-cluster scan surfaced 1 high-entropy cluster (600 queries) - "
        "review the dense-cluster findings above before allowlisting\n\n"
    )


# ── scan: all four variants (stable columns) + all-slow (empty middle) ───────
def test_golden_scan_all_four_variants():
    out = _render([
        _f("scan", Severity.HIGH, "192.0.2.10 → 198.51.100.20",
           {"scan_type": "vertical", "src": "192.0.2.10", "dst": "198.51.100.20",
            "scan_state_ratio": 0.911, "distinct_ports": 777}),
        _f("scan", Severity.HIGH, "192.0.2.11 → *:22",
           {"scan_type": "horizontal", "src": "192.0.2.11", "port": 22,
            "scan_state_ratio": 0.822, "distinct_hosts": 654}),
        _f("scan", Severity.MEDIUM, "192.0.2.12 → *",
           {"scan_type": "block", "src": "192.0.2.12", "scan_state_ratio": 0.733,
            "distinct_ports": 88, "distinct_hosts": 99}),
        _f("scan", Severity.LOW, "192.0.2.13",
           {"scan_type": "slow", "src": "192.0.2.13", "scan_state_ratio": 0.644,
            "distinct_ports": 31, "active_buckets": 17}),
    ])
    assert out == (
        f"\nscan - 4 findings · 2 high  1 medium  1 low\nMission for scan.\n{RULE}\n"
        "high    vertical    91% no normal close seen  192.0.2.10  → 198.51.100.20        777 ports\n"
        "high    horizontal  82% no normal close seen  192.0.2.11  → *:22                 654 hosts\n"
        "medium  block       73% no normal close seen  192.0.2.12  → *                    88p × 99h\n"
        "low     slow        64% no normal close seen  192.0.2.13                   31 ports/17 win\n\n"
    )


def test_golden_scan_all_slow_empty_middle_kept_by_text():
    out = _render([
        _f("scan", Severity.LOW, "192.0.2.13",
           {"scan_type": "slow", "src": "192.0.2.13", "scan_state_ratio": 0.644,
            "distinct_ports": 31, "active_buckets": 17}),
        _f("scan", Severity.LOW, "192.0.2.14",
           {"scan_type": "slow", "src": "192.0.2.14", "scan_state_ratio": 0.655,
            "distinct_ports": 22, "active_buckets": 12}),
    ])
    assert out == (
        f"\nscan - 2 findings · 2 low\nMission for scan.\n{RULE}\n"
        "low     slow  64% no normal close seen  192.0.2.13    31 ports/17 win\n"
        "low     slow  66% no normal close seen  192.0.2.14    22 ports/12 win\n\n"
    )


# ── syslog: privileged → rare events → bursts; ts-order within each ──
def test_golden_syslog_privileged_rare_events_and_bursts():
    out = _render([
        _f("syslog", Severity.MEDIUM, "useradd: sentinel privileged event 717171",
           {"host": "host-a", "template_id": 5, "template_str": "useradd: <*>",
            "count": 2, "threshold": 9, "privileged": True}),
        _f("syslog", Severity.LOW, "host-family",
           {"tier": "family", "host": "host-family", "program": "postfix/qmgr",
            "line_count": 2, "start_ts": 10.0, "end_ts": 7210.0,
            "span_seconds": 7200.0, "sample_raw": ["a", "b"],
            "member_fragments": ["family meat"], "label": None}),
        _f("syslog", Severity.LOW, "journal needle sentinel",
           {"host": "host-journal", "template_str": "cron: <*>",
            "count": 1, "threshold": 9,
            "first_seen": "2026-07-12T21:57:33+00:00", "self_stamped": False}),
        _f("syslog", Severity.INFO, "host-b",
           {"tier": "burst", "line_count": 13, "span_seconds": 47.0,
            "start_ts": 1.0, "end_ts": 48.0,
            "program_mix": [["CRON", 9], ["cron", 3], ["sshd", 1]],
            "sample_raw": ["a", "b"], "member_fragments": ["burst meat"],
            "label": "rebooted"}),
        _f("syslog", Severity.INFO, "host-a",
           {"tier": "reboot", "host": "host-a",
            "reboot_ts": "2026-06-01T03:04:05+00:00", "label": "rebooted"}),
    ])
    assert out == (
        f"\nsyslog - 5 findings · 1 medium  2 low  2 info\nMission for syslog.\n{RULE}\n"
        "privileged (1)\n"
        "  medium  useradd: sentinel privileged event 717171\n\n"
        "rare events (2)\n"
        "  low     Jan  1 00:00:10 · host-family · postfix/qmgr · "
        "2 rare lines · 2h\n"
        "        family meat\n"
        "  low     Jul 12 21:57:33 · journal needle sentinel\n\n"
        "bursts (2)\n"
        "  info    Jan  1 00:00:01 · host-b · rebooted · 13 rare lines · "
        "47s · mostly CRON, sshd\n"
        "        burst meat\n"
        "  info    Jun  1 03:04:05 · host-a · rebooted\n\n"
    )


def test_golden_syslog_transaction_row():
    out = _render([
        _f("syslog", Severity.INFO, "host-t",
           {"tier": "transaction", "label": "update run", "host": "host-t",
            "member_count": 2, "represented_line_count": 7,
            "start_ts": 1.0, "end_ts": 121.0,
            "first_seen": "1970-01-01T00:00:01+00:00", "span_seconds": 120.0,
            "program_mix": [["dnf", 4], ["DNF", 1], ["kernel", 2]],
            "member_fragments": ["tokens: installed package verified"],
            "members": [
                {"severity": "low", "tier": "family",
                 "represented_line_count": 5, "title": "host-t", "program": "dnf"},
                {"severity": "low", "tier": "family",
                 "represented_line_count": 2, "title": "host-t", "program": "kernel"},
            ]}),
    ])
    assert out == (
        f"\nsyslog - 1 finding · 1 info\nMission for syslog.\n{RULE}\n"
        "bursts (1)\n"
        "  info    Jan  1 00:00:01 · host-t · update run · "
        "7 rare lines · 2m · mostly dnf, kernel\n"
        "        tokens: installed package verified\n\n"
    )


def test_golden_syslog_burst_compact_span_and_singular_noun():
    one = _render([
        _f("syslog", Severity.INFO, "host-one",
           {"tier": "burst", "line_count": 1, "span_seconds": 105.0,
            "start_ts": 1.0, "end_ts": 106.0,
            "program_mix": [["CRON", 1], ["cron", 1], ["sshd", 1]],
            "sample_raw": ["one"], "label": None}),
    ])
    assert "host-one · 1 rare line · 2m · mostly CRON, sshd" in one

    two = _render([
        _f("syslog", Severity.INFO, "host-two",
           {"tier": "burst", "line_count": 4, "span_seconds": 2.0,
            "start_ts": 1.0, "end_ts": 3.0,
            "program_mix": [["kernel", 4]], "sample_raw": ["two"],
            "label": None}),
    ])
    assert "host-two · 4 rare lines · 2s · mostly kernel" in two

    zero = _render([
        _f("syslog", Severity.INFO, "host-zero",
           {"tier": "burst", "line_count": 4, "span_seconds": 0.0,
            "start_ts": 1.0, "end_ts": 1.0,
            "program_mix": [["kernel", 4]], "sample_raw": ["zero"],
            "label": None}),
    ])
    assert "host-zero · 4 rare lines · 0s · mostly kernel" in zero


# ── exfil: measured-byte flow rows ──────────────────────────────────────────
def test_golden_exfil_flow_row():
    out = _render([_f("exfil", Severity.MEDIUM, "192.0.2.10 → 198.51.100.20",
        {"src": "192.0.2.10", "dst": "198.51.100.20", "orig_bytes_total": 1_500_000_000,
         "resp_bytes_total": 500_000_000, "orig_share": 0.75, "connection_count": 3,
         "span_seconds": 14_400.0})])
    assert out == (
        f"\nexfil - 1 finding · 1 medium\nMission for exfil.\n{RULE}\n"
        "medium  192.0.2.10  →  198.51.100.20  out=1.4 GB  "
        "75.00% sent  conns=3  4h\n\n"
    )


def test_golden_exfil_multi_service_transport_row_width_is_measured() -> None:
    out = _render([_f("exfil", Severity.MEDIUM, "192.0.2.10 → 198.51.100.20",
        {"src": "192.0.2.10", "dst": "198.51.100.20", "orig_bytes_total": 1_500_000_000,
         "resp_bytes_total": 500_000_000, "orig_share": 0.75, "connection_count": 3,
         "span_seconds": 14_400.0,
         "port_mix": "443/tcp (1.0 GB), 8443/tcp (400 MB)"})])
    row = next(line for line in out.splitlines() if "192.0.2.10" in line)
    assert row == (
        "medium  192.0.2.10  →  198.51.100.20  out=1.4 GB  "
        "75.00% sent  443/tcp (1.0 GB), 8443/tcp (400 MB)  conns=3  4h"
    )
    assert len(row) == 111  # measured after natural composition; not a design estimate


def test_golden_exfil_demo_row_width_is_measured_against_baseline() -> None:
    out = _render([_f("exfil", Severity.MEDIUM, "192.168.1.37 → 203.0.113.77",
        {"src": "192.168.1.37", "dst": "203.0.113.77",
         "orig_bytes_total": 2_000_000_000, "resp_bytes_total": 45_820_858,
         "orig_share": 0.9776, "connection_count": 12,
         "span_seconds": 3_300.0, "port_mix": "443/tcp (1.9 GB)"})])
    row = next(line for line in out.splitlines() if "192.168.1.37" in line)
    assert row == (
        "medium  192.168.1.37  →  203.0.113.77  out=1.9 GB  "
        "97.76% sent  443/tcp (1.9 GB)  conns=12  55m"
    )
    assert len(row) == 95  # measured real demo route; the prior row was 78


def test_golden_exfil_optional_span_vanishes():
    out = _render([_f("exfil", Severity.MEDIUM, "192.0.2.11 → 198.51.100.21",
        {"src": "192.0.2.11", "dst": "198.51.100.21", "orig_bytes_total": 1_000,
         "resp_bytes_total": 0, "orig_share": 1.0, "connection_count": 1,
         "span_seconds": None})])
    assert out == (
        f"\nexfil - 1 finding · 1 medium\nMission for exfil.\n{RULE}\n"
        "medium  192.0.2.11  →  198.51.100.21  out=1000 B  "
        "100.00% sent  conns=1\n\n"
    )


# ── aws: burst, ranked, ranked_summary (full-width prose) ────────────────────
def test_golden_aws_burst_ranked_summary():
    out = _render([
        _f("aws", Severity.MEDIUM, "role/sentinel-burst",
           {"tier": "burst", "principal": "role/sentinel-burst", "span_seconds": 4567.0,
            "new_action_count": 13, "new_service_count": 4, "error_rate": 0.27,
            "mean_rarity": 2.1, "new_actions": ["a1"], "new_services": ["s1"]}),
        _f("aws", Severity.LOW, "role/sentinel-rank",
           {"tier": "ranked", "principal": "role/sentinel-rank", "composite_z": 3.14,
            "error_rate": 0.05, "event_count": 424, "distinct_source_ip": 6}),
        _f("aws", Severity.INFO, "ranked tier: no principals cleared the LOW band",
           {"tier": "ranked_summary", "scorable_count": 11, "top_principal": "role/topdog",
            "top_composite_z": 2.71}),
    ])
    assert out == (
        f"\naws - 3 findings · 1 medium  1 low  1 info\nMission for aws.\n{RULE}\n"
        "burst sweeps (1)\n"
        "  medium  role/sentinel-burst  13 new  4 svc  1h  err=27%\n\n"
        "ranked principals (2)\n"
        "  low     role/sentinel-rank  z=3.14  err=5%  424 ev  6 ip\n"
        "  info    ranked tier: no principals cleared the LOW band  (11 scored; top role/topdog z=2.71)\n\n"
    )


# ── cap-disclosure line ──────────────────────────────────────────────────────
def test_golden_cap_disclosure():
    findings = [_f("beacon", Severity.MEDIUM, f"192.0.2.{i} → 198.51.100.20:443/tcp",
        {"src_ip": f"192.0.2.{i}", "dst_ip": "198.51.100.20", "dst_port": 443,
         "proto": "tcp", "period_str": "60.0m", "beacon_score": 0.6,
         "conn_count": 100 + i}) for i in (10, 11, 12)]
    out = _render(findings, cap=1)
    assert out == (
        f"\nbeacon - 3 findings · 3 medium\nMission for beacon.\n{RULE}\n"
        "medium  192.0.2.10  →  198.51.100.20:443/tcp   period=60.0m   rhythm=0.600   110 conns\n\n"
        "… 2 more not shown (showing first 1). Unusually high - narrow with the "
        "allowlist, or this detector may be misbehaving.\n\n"
    )


# ── verbose tails (L1 curated, L2 full) - must stay byte-identical ───────────
_BEACON_VERBOSE = _f(
    "beacon", Severity.MEDIUM, "192.0.2.10 → 198.51.100.20:443/tcp",
    {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": 443, "proto": "tcp",
     "period_str": "60.0m", "beacon_score": 0.6083, "conn_count": 918273,
     "spectral_ratio": 0.71, "prominence_norm": 0.55, "jitter_cv": 0.12},
    description="A regular beat to a fixed destination.",
    next_steps=["Inspect the flow"],
)


def test_golden_verbose_tail_level_1_curated():
    out = _render([_BEACON_VERBOSE], level=1)
    assert out == (
        f"\nbeacon - 1 finding · 1 medium\nMission for beacon.\n{RULE}\n"
        "medium  192.0.2.10  →  198.51.100.20:443/tcp   period=60.0m   rhythm=0.608   918,273 conns\n"
        "     A regular beat to a fixed destination.\n"
        "     next steps:\n"
        "       · Inspect the flow\n"
        "     evidence:\n"
        "       beacon_score: 0.6083\n"
        "       spectral_ratio: 0.71\n"
        "       prominence_norm: 0.55\n"
        "       jitter_cv: 0.12\n"
        "       conn_count: 918273\n"
        "       period_str: 60.0m\n"
        "     data window: 2026-06-01 12:00 → 2026-06-01 18:30 local  (6h)\n\n"
    )


def test_golden_verbose_tail_level_2_full():
    out = _render([_BEACON_VERBOSE], level=2)
    assert out == (
        f"\nbeacon - 1 finding · 1 medium\nMission for beacon.\n{RULE}\n"
        "medium  192.0.2.10  →  198.51.100.20:443/tcp   period=60.0m   rhythm=0.608   918,273 conns\n"
        "     A regular beat to a fixed destination.\n"
        "     next steps:\n"
        "       · Inspect the flow\n"
        "     evidence:\n"
        "       src_ip: 192.0.2.10\n"
        "       dst_ip: 198.51.100.20\n"
        "       dst_port: 443\n"
        "       proto: tcp\n"
        "       period_str: 60.0m\n"
        "       beacon_score: 0.6083\n"
        "       conn_count: 918273\n"
        "       spectral_ratio: 0.71\n"
        "       prominence_norm: 0.55\n"
        "       jitter_cv: 0.12\n"
        "     data window: 2026-06-01 12:00 → 2026-06-01 18:30 local  (6h)\n\n"
    )
