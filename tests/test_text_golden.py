"""Byte-output golden pins for the text reading surface, per detector/variant.

GOLDEN SAFETY NET: these pin the EXACT text output for the text reading surface.
The render pipeline + cell projection live in ``outputs/_render_model.py``; every
assertion below must stay byte-identical (zero snapshot churn). RFC 5737 fixtures;
sentinel-ish values.

Timestamps are pinned to UTC by the conftest session fixture, so the verbose
``data window`` line is deterministic.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from sigwood.common.finding import Finding, Severity
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
    TextHandler(stream=buf, verbose_level=level, max_findings_per_detector=cap).write(findings)
    return buf.getvalue()


# ── beacon ───────────────────────────────────────────────────────────────────
def test_golden_beacon():
    out = _render([_f("beacon", Severity.HIGH, "192.0.2.10 → 198.51.100.20:443/tcp",
        {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": 443,
         "proto": "tcp", "period_str": "60.0m", "beacon_score": 0.6083,
         "conn_count": 918273})])
    assert out == (
        f"\nbeacon - 1 finding · 1 H\n{RULE}\n"
        "[H]  192.0.2.10  →  198.51.100.20:443/tcp   period=60.0m   score=0.608   918,273 conns\n\n"
    )


# ── dns: singleton (blocked column vanishes / appears) + group ───────────────
def test_golden_dns_singleton_no_blocked_column():
    out = _render([_f("dns", Severity.MEDIUM, "weirddomain.example",
        {"source": "zeek", "label_score": 4.7771, "query_count": 531, "unique_sources": 7})])
    assert out == (
        f"\ndns - 1 finding · 1 M\n{RULE}\n"
        "singletons (1)\n"
        "  [M]   score=4.78  531 qry  7 src  weirddomain.example\n\n"
    )


def test_golden_dns_singleton_blocked_column_present():
    out = _render([_f("dns", Severity.HIGH, "blockeddomain.example",
        {"source": "pihole", "label_score": 4.9112, "query_count": 612,
         "unique_sources": 3, "was_blocked": True, "block_ratio": 0.5})])
    assert out == (
        f"\ndns - 1 finding · 1 H\n{RULE}\n"
        "singletons (1)\n"
        "  [H]   score=4.91  612 qry  3 src  BLOCKED  blockeddomain.example\n\n"
    )


def test_golden_dns_group():
    out = _render([_f("dns", Severity.MEDIUM, "example.net",
        {"source": "zeek", "registrable_domain": "example.net", "subdomain_count": 42,
         "max_label_score": 4.9001, "min_label_score": 3.1002, "total_queries": 8123,
         "unique_sources": 9})])
    assert out == (
        f"\ndns - 1 finding · 1 M\n{RULE}\n"
        "groups (1)\n"
        "  [M]   42 sub  score=4.90-3.10  8123 qry  9 src  example.net\n\n"
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
        f"\ndns - 2 findings · 1 H  1 I\n{RULE}\n"
        "groups (1)\n"
        "  [H]   600 sub  score=2.19-1.97  600 qry  1 src  tunnel.example\n\n"
        "dense-cluster scan (1)\n"
        "  [I]   dense-cluster scan surfaced 1 high-entropy cluster (600 queries) - review before allowlisting\n\n"
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
        f"\nscan - 4 findings · 2 H  1 M  1 L\n{RULE}\n"
        "[H]   vertical    ratio=0.91  192.0.2.10  → 198.51.100.20        777 ports\n"
        "[H]   horizontal  ratio=0.82  192.0.2.11  → *:22                 654 hosts\n"
        "[M]   block       ratio=0.73  192.0.2.12  → *                    88p × 99h\n"
        "[L]   slow        ratio=0.64  192.0.2.13                   31 ports/17 win\n\n"
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
        f"\nscan - 2 findings · 2 L\n{RULE}\n"
        "[L]   slow  ratio=0.64  192.0.2.13    31 ports/17 win\n"
        "[L]   slow  ratio=0.66  192.0.2.14    22 ports/12 win\n\n"
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
            "program_mix": [["kernel", 9], ["systemd", 4]],
            "sample_raw": ["a", "b"], "member_fragments": ["burst meat"],
            "label": "rebooted"}),
        _f("syslog", Severity.INFO, "host-a",
           {"tier": "reboot", "host": "host-a",
            "reboot_ts": "2026-06-01T03:04:05+00:00", "label": "rebooted"}),
    ])
    assert out == (
        f"\nsyslog - 5 findings · 1 M  2 L  2 I\n{RULE}\n"
        "privileged (1)\n"
        "  [M]   useradd: sentinel privileged event 717171\n\n"
        "rare events (2)\n"
        "  [L]   Jan  1 00:00:10 · host-family · postfix/qmgr · "
        "2 rare lines · 2h\n"
        "        family meat\n"
        "  [L]   Jul 12 21:57:33 · journal needle sentinel\n\n"
        "bursts (2)\n"
        "  [I]   Jan  1 00:00:01 · host-b · rebooted · 13 rare lines · "
        "47s · mostly kernel, systemd\n"
        "        burst meat\n"
        "  [I]   Jun  1 03:04:05 · host-a · rebooted\n\n"
    )


# ── duration: split flow, with and without states (rstrip) ───────────────────
def test_golden_duration_with_states():
    out = _render([_f("duration", Severity.HIGH, "192.0.2.10 → 198.51.100.20:443/tcp",
        {"src": "192.0.2.10", "dst": "198.51.100.20", "port": 443, "proto": "tcp",
         "max_duration_str": "4h 0m", "connection_count": 3,
         "avg_bytes_per_second": 1500000.0, "conn_states": ["SF", "S1"]})])
    assert out == (
        f"\nduration - 1 finding · 1 H\n{RULE}\n"
        "[H]  192.0.2.10  →  198.51.100.20:443/tcp  4h 0m  1.5mbps  3 conns  SF, S1\n\n"
    )


def test_golden_duration_no_states_rstrip():
    out = _render([_f("duration", Severity.MEDIUM, "192.0.2.11 → 198.51.100.21:993/tcp",
        {"src": "192.0.2.11", "dst": "198.51.100.21", "port": 993, "proto": "tcp",
         "max_duration_str": "2h 5m", "connection_count": 1,
         "avg_bytes_per_second": None, "conn_states": []})])
    assert out == (
        f"\nduration - 1 finding · 1 M\n{RULE}\n"
        "[M]  192.0.2.11  →  198.51.100.21:993/tcp  2h 5m    1 conn\n\n"
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
        f"\naws - 3 findings · 1 M  1 L  1 I\n{RULE}\n"
        "burst sweeps (1)\n"
        "  [M]   role/sentinel-burst  13 new  4 svc  1h  err=27%\n\n"
        "ranked principals (2)\n"
        "  [L]   role/sentinel-rank  z=3.14  err=5%  424 ev  6 ip\n"
        "  [I]   ranked tier: no principals cleared the LOW band  (11 scored; top role/topdog z=2.71)\n\n"
    )


# ── cap-disclosure line ──────────────────────────────────────────────────────
def test_golden_cap_disclosure():
    findings = [_f("beacon", Severity.HIGH, f"192.0.2.{i} → 198.51.100.20:443/tcp",
        {"src_ip": f"192.0.2.{i}", "dst_ip": "198.51.100.20", "dst_port": 443,
         "proto": "tcp", "period_str": "60.0m", "beacon_score": 0.6,
         "conn_count": 100 + i}) for i in (10, 11, 12)]
    out = _render(findings, cap=1)
    assert out == (
        f"\nbeacon - 3 findings · 3 H\n{RULE}\n"
        "[H]  192.0.2.10  →  198.51.100.20:443/tcp   period=60.0m   score=0.600   110 conns\n\n"
        "… 2 more not shown (showing first 1). Unusually high - narrow with the "
        "allowlist, or this detector may be misbehaving.\n\n"
    )


# ── verbose tails (L1 curated, L2 full) - must stay byte-identical ───────────
_BEACON_VERBOSE = _f(
    "beacon", Severity.HIGH, "192.0.2.10 → 198.51.100.20:443/tcp",
    {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": 443, "proto": "tcp",
     "period_str": "60.0m", "beacon_score": 0.6083, "conn_count": 918273,
     "spectral_ratio": 0.71, "prominence_norm": 0.55, "jitter_cv": 0.12},
    description="A regular beat to a fixed destination.",
    next_steps=["Inspect the flow"],
)


def test_golden_verbose_tail_level_1_curated():
    out = _render([_BEACON_VERBOSE], level=1)
    assert out == (
        f"\nbeacon - 1 finding · 1 H\n{RULE}\n"
        "[H]  192.0.2.10  →  198.51.100.20:443/tcp   period=60.0m   score=0.608   918,273 conns\n"
        "     A regular beat to a fixed destination.\n"
        "     evidence:\n"
        "       beacon_score: 0.6083\n"
        "       spectral_ratio: 0.71\n"
        "       prominence_norm: 0.55\n"
        "       jitter_cv: 0.12\n"
        "       conn_count: 918273\n"
        "       period_str: 60.0m\n"
        "     next steps:\n"
        "       · Inspect the flow\n"
        "     data window: 2026-06-01 12:00 → 2026-06-01 18:30 local  (6h)\n\n"
    )


def test_golden_verbose_tail_level_2_full():
    out = _render([_BEACON_VERBOSE], level=2)
    assert out == (
        f"\nbeacon - 1 finding · 1 H\n{RULE}\n"
        "[H]  192.0.2.10  →  198.51.100.20:443/tcp   period=60.0m   score=0.608   918,273 conns\n"
        "     A regular beat to a fixed destination.\n"
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
        "     next steps:\n"
        "       · Inspect the flow\n"
        "     data window: 2026-06-01 12:00 → 2026-06-01 18:30 local  (6h)\n\n"
    )
