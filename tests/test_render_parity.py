"""Row-scoped signal-parity tripwire: text ↔ html(↔pdf).

The guarded bug class is text and html DRIFTING on what a finding renders.
This pins parity at the source: every NON-empty ``project_row`` cell must render
its datum in BOTH surfaces - compared PER detector / variant / row (a global
"value in text and value in html" sweep is explicitly NOT acceptable). Fixtures
carry UNIQUE SENTINEL values so a match is attributable to its row, not a
coincidental common int.

The two surfaces render the datum DIFFERENTLY by design: text keeps the labeled
``Cell.value`` (``period=61.5m``); html shows the header-stripped
``html_cell_value(cell)`` (``61.5m``) beneath a ``period`` header, so the label
is not double-printed. Parity is checked per-surface against what that surface
shows; the html value is a substring of text's, so the shared datum is pinned.
"""

from __future__ import annotations

import html as _htmllib
import io
import math
import re
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from sigwood.common.display import set_display_utc
from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.detectors.scan import SCAN_STATES
from sigwood.outputs._evidence import (
    description_for_reading,
    evidence_at_level,
    format_evidence_for_reading,
)
from sigwood.outputs._render_model import (
    Section,
    html_cell_value,
    project_row,
    section_columns,
)
from sigwood.outputs.html import render_report_html
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler

_W = (
    datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
    datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
)


def _f(detector, severity, title, evidence):
    return Finding(detector=detector, severity=severity, title=title, description="",
                   evidence=evidence, next_steps=[], ts_generated=_W[1], data_window=_W)


def _text(findings, level=0):
    buf = io.StringIO()
    handler = TextHandler(stream=buf, verbose_level=level, max_findings_per_detector=100)
    handler.begin(_summary(findings))
    handler.write(findings)
    return buf.getvalue()


def _html_text(findings, level=0):
    """Render html, strip tags, unescape - the visible text of the table."""
    raw = render_report_html(
        findings,
        _summary(findings),
        verbose_level=level,
        max_findings_per_detector=100,
    )
    stripped = re.sub(r"<[^>]+>", " ", raw)
    return _htmllib.unescape(stripped)


def _machine(handler_cls, findings) -> str:
    stream = io.StringIO()
    handler = handler_cls(stream=stream)
    handler.begin(_summary(findings))
    handler.write(findings)
    handler.end()
    return stream.getvalue()


def _summary(findings: list[Finding]) -> RunSummary:
    names = list(dict.fromkeys(finding.detector for finding in findings))
    return RunSummary(
        data_window=_W,
        record_counts={},
        data_size_bytes=0,
        detectors_run=names,
        detectors_skipped={},
        detector_missions={name: f"Mission for {name}." for name in names},
    )


# ── one finding per detector AND per variant, UNIQUE SENTINEL values ─────────
_VARIANTS: dict[str, Finding] = {
    "beacon": _f("beacon", Severity.MEDIUM, "x", {
        "src_ip": "192.0.2.211", "dst_ip": "198.51.100.222", "dst_port": 4433,
        "proto": "tcp", "period_str": "61.5m", "beacon_score": 0.6171, "conn_count": 918273}),
    "dns_singleton": _f("dns", Severity.MEDIUM, "sentineldomain.example", {
        "source": "zeek", "label_score": 4.7731, "query_count": 53117, "unique_sources": 71}),
    "dns_singleton_blocked": _f("dns", Severity.HIGH, "blockeddomain.example", {
        "source": "pihole", "label_score": 4.6621, "query_count": 6121, "unique_sources": 31,
        "was_blocked": True, "block_ratio": 0.5}),
    "dns_group": _f("dns", Severity.MEDIUM, "g", {
        "source": "zeek", "registrable_domain": "sentinelgroup.example",
        "subdomain_count": 4217, "max_label_score": 4.9117, "min_label_score": 3.1127,
        "total_queries": 81237, "unique_sources": 91}),
    "dns_pihole_dense": _f("dns", Severity.MEDIUM, "sentineldense.example", {
        "source": "pihole", "origin": "dense_cluster", "severity_basis": [],
        "registrable_domain": "sentineldense.example", "subdomain_count": 4319,
        "max_label_score": 4.9231, "min_label_score": 3.1231,
        "total_queries": 82319, "unique_sources": 93,
        "was_blocked": False, "block_ratio": 0.0}),
    "scan_vertical": _f("scan", Severity.HIGH, "x", {
        "scan_type": "vertical", "src": "192.0.2.231", "dst": "198.51.100.241",
        "scan_state_ratio": 0.9117, "distinct_ports": 7717}),
    "scan_horizontal": _f("scan", Severity.HIGH, "x", {
        "scan_type": "horizontal", "src": "192.0.2.232", "port": 2237,
        "scan_state_ratio": 0.8227, "distinct_hosts": 6547}),
    "scan_block": _f("scan", Severity.MEDIUM, "x", {
        "scan_type": "block", "src": "192.0.2.233", "scan_state_ratio": 0.7337,
        "distinct_ports": 887, "distinct_hosts": 997}),
    "scan_slow": _f("scan", Severity.LOW, "x", {
        "scan_type": "slow", "src": "192.0.2.234", "scan_state_ratio": 0.6447,
        "distinct_ports": 317, "active_buckets": 177}),
    "scan_rollup": _f("scan", Severity.HIGH, "192.0.2.235 → *", {
        "tier": "rollup", "scan_type": "vertical", "src": "192.0.2.235",
        "member_count": 5, "target_count": 5, "total_conns": 1517,
        "max_scan_state_ratio": 0.9557,
        "members": [{
            "scan_type": "vertical", "src": "192.0.2.235",
            "dst": "198.51.100.245", "distinct_ports": 61, "distinct_hosts": 1,
            "total_conns": 307, "scan_state_ratio": 0.9557}]}),
    "syslog_event": _f("syslog", Severity.LOW, "kernel: sentinel-evt-717117", {
        "host": "host-sentinel-9", "template_str": "kernel: <*>", "count": 2, "threshold": 9}),
    "syslog_stamped_event": _f(
        "syslog", Severity.LOW, "journal-stamped-sentinel-727117", {
            "host": "host-journal-9", "template_str": "cron: <*>",
            "count": 1, "threshold": 9,
            "first_seen": "2026-07-12T21:57:33+00:00",
            "self_stamped": False,
        }),
    "syslog_family": _f("syslog", Severity.LOW, "host-sentinel-family-9", {
        "tier": "family", "host": "host-sentinel-family-9",
        "program": "progsentinel", "line_count": 137, "span_seconds": 7320.0,
        "start_ts": 1.0, "end_ts": 7321.0,
        "sample_raw": ["family-raw-sentinel-a"],
        "member_fragments": ["family-fragment-sentinel-717"], "label": None}),
    "syslog_reboot": _f("syslog", Severity.INFO, "host-sentinel-reboot-9", {
        "tier": "reboot", "host": "host-sentinel-reboot-9",
        "reboot_ts": "2026-06-01T07:08:09+00:00", "label": "rebooted"}),
    "syslog_burst": _f("syslog", Severity.INFO, "host-sentinel-burst-9", {
        "tier": "burst", "line_count": 137, "span_seconds": 4577.0,
        "start_ts": 1.0, "end_ts": 4578.0,
        "program_mix": [["kernsentinel", 91], ["syssentinel", 41]],
        "sample_raw": ["raw-sentinel-a", "raw-sentinel-b"],
        "member_fragments": ["burst-fragment-sentinel-727"], "label": "rebooted"}),
    "syslog_transaction": _f("syslog", Severity.INFO, "host-sentinel-txn-9", {
        "tier": "transaction", "label": "update run", "host": "host-sentinel-txn-9",
        "member_count": 2, "represented_line_count": 7,
        "start_ts": 1.0, "end_ts": 121.0,
        "first_seen": "1970-01-01T00:00:01+00:00", "span_seconds": 120.0,
        "program_mix": [["dnfsentinel", 5], ["kernsentinel", 2]],
        "member_fragments": ["transaction-fragment-sentinel-737"],
        "members": [
            {"severity": "low", "tier": "family", "represented_line_count": 5,
             "title": "host-sentinel-txn-9", "program": "dnfsentinel"},
            {"severity": "low", "tier": "family", "represented_line_count": 2,
             "title": "host-sentinel-txn-9", "program": "kernsentinel"},
        ],
    }),
    "ssl_two_leg": _f("ssl", Severity.MEDIUM, "x", {
        "src": "192.0.2.243", "dst": "198.51.100.253",
        "severity_basis": ["sni_absent", "validation"], "conn_count": 4127,
        "leg_a_count": 17, "leg_b_count": 4110,
        "validation_status": "self signed certificate",
        "tls_versions": {"TLSv12": 4127}, "port_mix": "9973 (4127)",
        "first_seen": "2026-08-01T00:00:00+00:00",
        "last_seen": "2026-08-01T04:17:00+00:00", "span_seconds": 15_420.0}),
    "ssl_one_leg": _f("ssl", Severity.LOW, "x", {
        "src": "192.0.2.244", "dst": "198.51.100.254",
        "severity_basis": ["sni_absent"], "conn_count": 61,
        "leg_a_count": 61, "leg_b_count": 0,
        "tls_versions": {"TLSv13": 61}, "port_mix": "9974 (61)",
        "first_seen": "2026-08-01T00:00:00+00:00"}),
    "dnsblock_arrival_strong": _f("dnsblock", Severity.LOW, "192.0.2.10 → family-a", {
        "kind": "arrival", "coverage_lane": "strong", "address": "192.0.2.10",
        "qualifying_name_count": 3, "attributed_query_count": 17,
        "active_periods": 2, "eligible_periods": 5,
        "first_associated_period": "2026-08-01T00:00:00+00:00",
        "history_seconds": 86400.0, "prior_other_address_count": 7,
        "prior_other_address_count_at_cap": False,
    }),
    "dnsblock_arrival_weak": _f("dnsblock", Severity.LOW, "192.0.2.11 → family-b", {
        "kind": "arrival", "coverage_lane": "weak", "address": "192.0.2.11",
        "qualifying_name_count": 4, "attributed_query_count": 19,
        "active_periods": 3, "eligible_periods": 6,
        "first_associated_period": "2026-08-02T00:00:00+00:00",
        "history_seconds": 172800.0, "prior_other_address_count": 100,
        "prior_other_address_count_at_cap": True,
    }),
    "dnsblock_burst": _f("dnsblock", Severity.LOW, "192.0.2.12 → family-c", {
        "kind": "burst", "coverage_lane": "strong", "address": "192.0.2.12",
        "peak_count": 401, "baseline_median_twice": 25,
        "active_periods": 4, "eligible_periods": 7,
        "attributed_query_count": 777,
    }),
    "dnsblock_fold": _f("dnsblock", Severity.LOW, "192.0.2.13", {
        "kind": "arrival_fold", "coverage_lane": "strong", "address": "192.0.2.13",
        "member_count": 4, "earliest_first_associated_period": "2026-08-01T00:00:00+00:00",
        "history_seconds": 259200.0,
        "members": [
            {"family_key": "family-d", "first_associated_period": "2026-08-01T00:00:00+00:00"},
            {"family_key": "family-e", "first_associated_period": "2026-08-03T00:00:00+00:00"},
        ],
    }),
    "dnsblock_recurring": _f("dnsblock", Severity.INFO, "recurring blocked-name activity", {
        "kind": "recurring_activity", "coverage_lane": "strong", "pair_count": 1,
        "family_count": 1, "address_count": 1, "periods_required": 4,
        "periods_total": 7,
    }),
    "dnsblock_prior": _f("dnsblock", Severity.INFO, "names withheld from novelty", {
        "kind": "prior_handling_exclusions", "withheld_name_count": 2,
        "withheld_membership_count": 5,
    }),
    "exfil": _f("exfil", Severity.MEDIUM, "x", {
        "src": "192.0.2.241", "dst": "198.51.100.251",
        "orig_bytes_total": 1_700_000_000.0, "resp_bytes_total": 100_000.0,
        "orig_share": 0.9999, "connection_count": 37, "span_seconds": 15_420.0,
        "port_mix": "9931/tcp (1.7 GB)", "max_duration_seconds": 2.0,
        "first_seen": "2026-08-01T00:00:00+00:00", "last_seen": "2026-08-01T04:17:00+00:00"}),
    "exfil_pool": _f("exfil", Severity.MEDIUM, "x", {
        "tier": "destination_pool", "src": "192.0.2.242",
        "destination_network": "198.51.96.0/20", "destination_count": 4,
        "orig_bytes_total": 1_800_000_000.0, "resp_bytes_total": 200_000.0,
        "orig_share": 0.9998, "connection_count": 47, "span_seconds": 16_420.0,
        "members": [
            {"dst": f"198.51.100.{host}", "orig_bytes": 450_000_000.0,
             "resp_bytes": 50_000.0, "orig_share": 0.9998, "connection_count": 10}
            for host in range(20, 24)
        ],
    }),
    "aws_burst": _f("aws", Severity.MEDIUM, "role/sentinel-burst-7", {
        "tier": "burst", "principal": "role/sentinel-burst-7", "span_seconds": 4577.0,
        "new_action_count": 137, "new_service_count": 47, "error_rate": 0.27, "mean_rarity": 2.0}),
    "aws_ranked": _f("aws", Severity.LOW, "role/sentinel-rank-7", {
        "tier": "ranked", "principal": "role/sentinel-rank-7", "composite_z": 3.147,
        "error_rate": 0.057, "event_count": 4247, "distinct_source_ip": 67}),
    "aws_ranked_summary": _f("aws", Severity.INFO, "ranked tier: no principals cleared the LOW band", {
        "tier": "ranked_summary", "scorable_count": 117, "top_principal": "role/sentinel-top-7",
        "top_composite_z": 2.717}),
    "aws_ranked_summary_below_floor": _f(
        "aws", Severity.INFO, "ranked tier: too few principals to compare", {
            "tier": "ranked_summary", "scorable_count": 2, "population_floor": 5}),
    "dns_scan_summary": _f(
        "dns", Severity.INFO, "dense-cluster scan: high-entropy clusters surfaced", {
            "tier": "scan_summary", "cluster_count": 2, "total_members": 3217,
            "registrable_domains": ["sentineltunnel.example", "sentineldga.example"]}),
    "dns_unscanned_clusters": _f(
        "dns", Severity.INFO,
        "3218 domains formed 2 dense clusters; Pi-hole dense-cluster scanning was "
        "disabled for this run - these clusters were not analyzed.", {
            "tier": "unscanned_clusters", "cluster_count": 2,
            "total_members": 3218,
    }),
}

# A recurring-only context row deliberately vanishes at level 0 when there is
# no entity finding, so it is not a valid fixture for the automatic
# one-finding-per-surface parity sweep below. Dedicated dnsblock tests pair its
# projection and reading description directly.
_DNSBLOCK_RECURRING = _VARIANTS.pop("dnsblock_recurring")


def test_beacon_default_row_cells_stay_compact() -> None:
    assert [(cell.key, cell.value) for cell in project_row(_VARIANTS["beacon"])] == [
        (None, "192.0.2.211"),
        (None, "→"),
        (None, "198.51.100.222:4433/tcp"),
        ("period", "period=61.5m"),
        ("rhythm", "rhythm=0.617"),
        ("conns", "918,273 conns"),
    ]

    html_out = render_report_html(
        [_VARIANTS["beacon"]], _summary([_VARIANTS["beacon"]]),
        verbose_level=0, max_findings_per_detector=100,
    )
    assert '<th class="col-rhythm">rhythm</th>' in html_out
    assert '<td class="data">0.617</td>' in html_out
    assert "rhythm=0.617" not in html_out


def test_dns_copyable_metadata_is_exact_opt_in_and_machine_inert() -> None:
    singleton = _VARIANTS["dns_singleton"]
    group = _VARIANTS["dns_group"]
    beacon = _VARIANTS["beacon"]
    frozen = deepcopy([singleton, group, beacon])

    singleton_cells = project_row(singleton)
    group_cells = project_row(group)
    beacon_cells = project_row(beacon)

    assert [cell.copyable for cell in singleton_cells] == [
        False, False, False, False, True,
    ]
    assert [cell.copyable for cell in group_cells] == [
        False, False, False, False, False, True,
    ]
    assert not any(cell.copyable for cell in beacon_cells)
    assert [singleton, group, beacon] == frozen

    for machine in (JsonHandler, CsvHandler):
        payload = _machine(machine, [singleton, group, beacon])
        assert "copyable" not in payload


@pytest.mark.parametrize(
    ("basis", "status", "expected"),
    [
        (["sni_absent"], None, "no server name"),
        (
            ["validation"],
            "self-signed certificate in certificate chain",
            "certificate did not validate "
            "(self-signed certificate in certificate chain)",
        ),
        (
            ["sni_absent", "validation"],
            "self-signed certificate in certificate chain",
            "no server name; certificate did not validate "
            "(self-signed certificate in certificate chain)",
        ),
    ],
)
def test_ssl_projection_renders_the_three_reason_shapes(
    basis: list[str],
    status: str | None,
    expected: str,
) -> None:
    evidence = {
        "src": "192.0.2.10",
        "dst": "198.51.100.20",
        "severity_basis": basis,
        "conn_count": 29,
        "tls_versions": {"TLSv12": 29},
        "first_seen": "2026-08-01T00:00:00+00:00",
    }
    if status is not None:
        evidence["validation_status"] = status
    finding = _f("ssl", Severity.MEDIUM, "x", evidence)

    cells = project_row(finding)
    keyed = {cell.key: cell.value for cell in cells if cell.key is not None}
    assert [cell.key for cell in cells] == [
        None, None, None, "conns", "tls", "first", "reason",
    ]
    assert keyed["reason"] == expected
    assert keyed["tls"] == "tls=TLSv12"
    assert "basis" not in keyed and "status" not in keyed

    text_out = _text([finding])
    html_out = render_report_html(
        [finding], _summary([finding]), verbose_level=0,
        max_findings_per_detector=100,
    )
    assert expected in text_out and "tls=TLSv12" in text_out
    assert '<th class="col-reason">reason</th>' in html_out
    assert '<th class="col-tls">tls</th>' in html_out
    assert expected in html_out and ">TLSv12</td>" in html_out
    assert "col-basis" not in html_out and "col-status" not in html_out

    row_start = html_out.index('<tr class="finding-row')
    row_end = html_out.index("</tr>", row_start)
    row = html_out[row_start:row_end]
    assert f'<td class="data col-reason">{expected}</td>' in row
    assert 'class="data col-conns"' not in row
    assert 'class="data col-tls"' not in row
    assert 'class="data col-first"' not in row
    assert row.index(">29</td>") < row.index(">TLSv12</td>")
    assert row.index(">TLSv12</td>") < row.index(expected)

    screen_start = html_out.index("@media screen {")
    print_start = html_out.index("@media print")
    screen_block = html_out[screen_start:print_start]
    assert ".findings-table td.col-reason { white-space: normal; }" in screen_block
    assert screen_block.index(
        ".findings-table td.data { white-space: nowrap; }"
    ) < screen_block.index(
        ".findings-table td.col-reason { white-space: normal; }"
    )
    assert "td.col-reason" not in html_out[print_start:]


def test_ssl_reason_wrap_rule_does_not_move_non_ssl_html() -> None:
    findings = [_VARIANTS["dns_singleton"], _VARIANTS["syslog_family"]]
    html_out = render_report_html(
        findings,
        _summary(findings),
        verbose_level=0,
        max_findings_per_detector=100,
    )
    assert ".findings-table td.col-reason { white-space: normal; }" not in html_out


def test_ssl_reason_fallback_never_invents_a_qualified_claim() -> None:
    finding = _f("ssl", Severity.LOW, "x", {
        "src": "192.0.2.10", "dst": "198.51.100.20",
        "severity_basis": ["validation", "future_leg"],
        "conn_count": 1,
    })
    reason = next(
        cell.value for cell in project_row(finding) if cell.key == "reason"
    )
    assert reason == "validation; future_leg"
    assert "certificate did not validate" not in reason


def test_ssl_reading_transform_is_detached_strict_and_ordered() -> None:
    finding = _f("ssl", Severity.LOW, "x", {})
    selected = {
        "first_seen": "2026-08-01T00:00:00+00:00",
        "tuple": "TLSv12|cipher-name|secp256r1|-",
        "tuple_share": 0.052069,
        "span_seconds": 129_600.0,
    }
    frozen = deepcopy(selected)

    rendered = format_evidence_for_reading(finding, selected)
    assert list(rendered) == [
        "first_seen", "version", "cipher", "curve", "alpn",
        "setup share", "span",
    ]
    assert rendered["version"] == "TLSv12"
    assert rendered["cipher"] == "cipher-name"
    assert rendered["curve"] == "secp256r1"
    assert rendered["alpn"] == "not recorded"
    assert rendered["setup share"] == "5.21% of loaded sessions"
    assert rendered["span"] == "1.5d"
    assert selected == frozen


def test_ssl_tuple_null_and_malformed_fallback_contract() -> None:
    finding = _f("ssl", Severity.LOW, "x", {})
    labels = ("version", "cipher", "curve", "alpn")
    for null_index in range(4):
        parts = ["v", "c", "g", "a"]
        parts[null_index] = "-"
        rendered = format_evidence_for_reading(
            finding,
            {"tuple": "|".join(parts)},
        )
        assert rendered[labels[null_index]] == "not recorded"
        assert list(rendered) == list(labels)

    for malformed in ("v|c|g", "v|c|g|a|extra", ["v", "c", "g", "a"]):
        rendered = format_evidence_for_reading(finding, {"tuple": malformed})
        assert rendered == {"tuple": malformed}


def test_ssl_numeric_fallback_retains_unrenderable_machine_values() -> None:
    finding = _f("ssl", Severity.LOW, "x", {})
    for value in (True, "0.5", float("inf"), float("nan"), 10**1000):
        selected = {"span_seconds": value, "tuple_share": value}
        rendered = format_evidence_for_reading(finding, selected)
        assert set(rendered) == {"span_seconds", "tuple_share"}
        if isinstance(value, float) and math.isnan(value):
            assert math.isnan(rendered["span_seconds"])
            assert math.isnan(rendered["tuple_share"])
        else:
            assert rendered == selected

    # A finite share remains renderable even when the same finite number is
    # too large for timedelta; the failed span conversion keeps its machine key.
    enormous = format_evidence_for_reading(
        finding,
        {"span_seconds": 1e308, "tuple_share": 1e308},
    )
    assert set(enormous) == {"span_seconds", "setup share"}
    assert enormous["span_seconds"] == 1e308
    assert enormous["setup share"].endswith("% of loaded sessions")


def test_ssl_evidence_rewrites_share_one_tier_policy_on_text_and_html() -> None:
    finding = _f("ssl", Severity.MEDIUM, "x", {
        "src": "192.0.2.10", "dst": "198.51.100.20",
        "severity_basis": ["sni_absent", "validation"],
        "conn_count": 29,
        "validation_status": "self signed certificate",
        "tuple": "TLSv12|cipher-name|secp256r1|-",
        "tuple_share": 0.052069,
        "span_seconds": 129_600.0,
        "tls_versions": {"TLSv12": 29},
        "port_mix": "443 (29)",
        "first_seen": "2026-08-01T00:00:00+00:00",
    })
    selected_v = evidence_at_level(finding, 1)
    selected_vv = evidence_at_level(finding, 2)
    assert "tuple" in selected_v
    assert "tuple_share" not in selected_v and "span_seconds" not in selected_v
    assert "tuple_share" in selected_vv and "span_seconds" in selected_vv

    text_v = _text([finding], level=1)
    text_vv = _text([finding], level=2)
    html_v = _html_text([finding], level=1)
    html_vv = _html_text([finding], level=2)
    for output in (text_v, html_v):
        assert "version" in output and "cipher-name" in output
        assert "alpn" in output and "not recorded" in output
        assert "setup share" not in output and "span_seconds" not in output
        # Curated validation_status deliberately repeats the measured qualifier
        # from the reason cell; dropping it would change CSV's signals.
        assert output.count("self signed certificate") == 2
    assert "setup share: 5.21% of loaded sessions" in text_vv
    assert "span: 1.5d" in text_vv
    assert "setup share" in html_vv and "5.21% of loaded sessions" in html_vv
    assert "span" in html_vv and "1.5d" in html_vv
    for output in (text_vv, html_vv):
        assert "tuple_share" not in output and "span_seconds" not in output


def test_dnsblock_projection_translates_days_prior_and_context_title() -> None:
    strong = project_row(_VARIANTS["dnsblock_arrival_strong"])
    weak = project_row(_VARIANTS["dnsblock_arrival_weak"])
    burst = project_row(_VARIANTS["dnsblock_burst"])
    prior = project_row(_VARIANTS["dnsblock_prior"])
    recurring = project_row(_DNSBLOCK_RECURRING)

    assert next(cell.value for cell in strong if cell.key == "days") == (
        "2 of 5 covered days"
    )
    assert next(cell.value for cell in weak if cell.key == "days") == (
        "3 of 6 days with data"
    )
    assert next(cell.value for cell in burst if cell.key == "days") == (
        "4 of 7 covered days"
    )
    assert next(cell.value for cell in strong if cell.key == "prior") == (
        "7 other addresses queried it"
    )
    assert next(cell.value for cell in weak if cell.key == "prior") == (
        "100+ other addresses queried it"
    )
    assert prior[0].value == (
        "names not reported as new, because Pi-hole had already handled them"
    )
    assert recurring[0].value == "recurring blocked-name activity"

    raw_html = render_report_html(
        [_VARIANTS["dnsblock_arrival_strong"]],
        _summary([_VARIANTS["dnsblock_arrival_strong"]]),
        verbose_level=0,
        max_findings_per_detector=100,
    )
    assert '<th class="num col-days">days</th>' in raw_html
    assert "periods" not in _text([_VARIANTS["dnsblock_arrival_strong"]])


@pytest.mark.parametrize(
    ("variant", "expected"),
    [
        (
            "dnsblock_arrival_strong",
            "This address had not queried this group of blocked names anywhere in the "
            "covered history, so the behaviour is new for this pair rather than the name "
            "being new. The queries fell on 2 of 5 covered days.",
        ),
        (
            "dnsblock_arrival_weak",
            "These names were first seen for this address in the rows available, which "
            "cannot prove there were no earlier queries because these logs cannot confirm "
            "complete daily coverage. The queries fell on 3 of 6 days with data.",
        ),
        (
            "dnsblock_burst",
            "Queries from this address for this group of blocked names reached 401 in one "
            "day, clearing the volume this check requires and rising well above its own "
            "median of 12.5 on other active days. Pi-hole records each query; what this "
            "adds is the comparison against this address's own other days.",
        ),
        (
            "dnsblock_fold",
            "This address began querying 4 separate groups of blocked names, condensed "
            "here into one row. Each group keeps its own counts and first-seen day in the "
            "machine evidence.",
        ),
        (
            "dnsblock_recurring",
            "1 address and name-group pair kept appearing on at least 4 of 7 fully covered "
            "days without meeting any other reporting bar. Persistence across days is the "
            "only reason they appear here.",
        ),
        (
            "dnsblock_prior",
            "2 names, covering 5 address-and-name pairings, were held back from the "
            "first-activity results because Pi-hole had already logged forwarded or cached "
            "handling for them on an earlier day. They are not new arrivals, so reporting "
            "them would overstate what the data shows; no action is needed.",
        ),
    ],
)
def test_dnsblock_descriptions_are_detached_and_shared(
    variant: str,
    expected: str,
) -> None:
    finding = deepcopy(
        _DNSBLOCK_RECURRING if variant == "dnsblock_recurring" else _VARIANTS[variant]
    )
    finding.description = "machine description sentinel"
    frozen = deepcopy(finding)

    assert description_for_reading(finding) == expected
    for output in (_text([finding], level=1), _html_text([finding], level=1)):
        assert expected in output
        assert "machine description sentinel" not in output
    assert finding == frozen


def test_dnsblock_reading_fallback_never_invents_an_understood_lane() -> None:
    finding = deepcopy(_VARIANTS["dnsblock_arrival_strong"])
    finding.description = "machine description sentinel"
    finding.evidence["coverage_lane"] = "future-lane"
    assert description_for_reading(finding) == "machine description sentinel"
    days = next(cell.value for cell in project_row(finding) if cell.key == "days")
    assert days == "2/5 periods"

    del finding.evidence["active_periods"]
    assert description_for_reading(finding) == "machine description sentinel"


def test_dnsblock_human_rendering_keeps_machine_finding_bytes_unchanged() -> None:
    findings = [
        deepcopy(_VARIANTS[name])
        for name in (
            "dnsblock_arrival_strong",
            "dnsblock_arrival_weak",
            "dnsblock_burst",
            "dnsblock_fold",
            "dnsblock_prior",
        )
    ] + [deepcopy(_DNSBLOCK_RECURRING)]
    for finding in findings:
        finding.description = f"machine description for {finding.evidence['kind']}"
    frozen = deepcopy(findings)
    json_before = _machine(JsonHandler, findings)
    csv_before = _machine(CsvHandler, findings)

    for level in (0, 1, 2):
        assert "dnsblock" in _text(findings, level=level)
        assert "dnsblock" in _html_text(findings, level=level)

    assert findings == frozen
    assert _machine(JsonHandler, findings) == json_before
    assert _machine(CsvHandler, findings) == csv_before


@pytest.mark.parametrize("variant", list(_VARIANTS))
def test_row_signal_parity_text_and_html(variant: str) -> None:
    """Every NON-empty project_row cell of this row appears in BOTH surfaces.

    Row-scoped: the finding is rendered ALONE so a hit is attributable to it.
    Empty cells (e.g. dns blocked when not blocked) are SKIPPED - never asserted.
    """
    finding = _VARIANTS[variant]
    text_out = _text([finding])
    html_out = _html_text([finding])
    cells = project_row(finding)
    assert cells, f"{variant}: project_row produced no cells"

    checked = 0
    for cell in cells:
        if cell.value == "":
            continue  # empty optional / vanished cell - never assert presence
        html_val = html_cell_value(cell)  # header-stripped for keyed cols; bare cells unchanged
        # The DATUM must reach both surfaces. Whether text carries the label inline
        # or under a column header is a per-table grammar, pinned separately below.
        assert html_val in text_out, f"{variant}: {html_val!r} missing from TEXT"
        assert html_val in html_out, f"{variant}: {html_val!r} missing from HTML"
        checked += 1
    assert checked > 0, f"{variant}: no non-empty cells exercised"


def test_html_strips_redundant_keyed_labels() -> None:
    """The `period=61.5m under a period header` double-label bug class: for a keyed
    cell whose value embeds its own key as a `<key>=` / ` <key>` affix, the LABELED
    form is TEXT-only - html shows just the bare datum beneath its header. A keyed
    cell whose value does not embed the key (dur / bps / states / scan type) has no
    label to strip and is exempt."""
    for variant, finding in _VARIANTS.items():
        text_out = _text([finding])
        html_out = _html_text([finding])
        for cell in project_row(finding):
            if cell.key is None or cell.value == "":
                continue
            stripped = html_cell_value(cell)
            if stripped == cell.value:
                continue  # no embedded label - nothing to double-print
            assert cell.value not in html_out, (
                f"{variant}/{cell.key}: double-labeled {cell.value!r} leaked into HTML"
            )
            assert stripped in html_out, f"{variant}/{cell.key}: bare datum {stripped!r} missing from HTML"


def test_text_labels_a_keyed_column_inline_or_by_header() -> None:
    """A keyed datum is never left unlabelled in TEXT.

    Two table grammars ship. Most detectors repeat the label on every row
    (`period=61.5m`); the dns tables carry it once as a column header and print the
    bare datum beneath it. Either is fine - printing the datum with NEITHER is the
    defect this pins, and it is what a half-applied header change produces.

    Derived from the render, never a list of detector names: a stripped datum in text
    is what says the column is header-labelled, and the header is then required."""
    for variant, finding in _VARIANTS.items():
        text_out = _text([finding])
        for cell in project_row(finding):
            if cell.key is None or cell.value == "":
                continue
            stripped = html_cell_value(cell)
            if stripped == cell.value:
                continue  # value never embedded its key - no label to place
            if cell.value in text_out:
                continue  # labelled inline on every row
            assert stripped in text_out, (
                f"{variant}/{cell.key}: datum {stripped!r} missing from TEXT entirely"
            )
            # Label stripped, so some line must carry it as a header - and that line
            # is not the row itself, which holds the datum.
            assert any(
                cell.key in line and stripped not in line
                for line in text_out.split("\n")
            ), f"{variant}/{cell.key}: label stripped from TEXT with no column header"


def test_html_projectorless_detector_falls_back_to_title() -> None:
    """A detector with no project_row projector (project_row → []) must still show
    the finding's title as a spanning cell - mirrors text's generic _render_finding,
    never a bare severity pill (the removed-behavior gap)."""
    finding = _f("future", Severity.HIGH, "future-sentinel-title-XYZ", {"k": "v"})
    assert project_row(finding) == []  # no projector for this detector
    assert "future-sentinel-title-XYZ" in _html_text([finding])  # html surfaces it
    assert "future-sentinel-title-XYZ" in _text([finding])       # text already did


def test_dns_blocked_cell_skipped_when_absent() -> None:
    """Negative control: the optional blocked cell is empty on an unblocked dns
    singleton, so 'BLOCKED' appears in NEITHER surface (no vacuous empty assert)."""
    finding = _VARIANTS["dns_singleton"]
    assert any(c.key == "blocked" and c.value == "" for c in project_row(finding))
    assert "BLOCKED" not in _text([finding])
    assert "BLOCKED" not in _html_text([finding])


def test_syslog_family_without_timestamps_omits_span() -> None:
    finding = _f("syslog", Severity.LOW, "host-no-time", {
        "tier": "family", "host": "host-no-time", "program": "unknown",
        "line_count": 2, "start_ts": None, "end_ts": None,
        "span_seconds": None, "sample_raw": ["a", "b"], "label": None,
    })
    cells = project_row(finding)
    assert [cell.value for cell in cells] == [
        "host-no-time · unknown · 2 rare lines"
    ]
    assert cells[0].full_width is True
    assert section_columns(Section(None, [finding], 1)) == []
    assert "None" not in _text([finding])
    assert "None" not in _html_text([finding])


def test_syslog_first_cell_is_keyed_for_html_but_bare_in_text() -> None:
    finding = _f("syslog", Severity.LOW, "host-first", {
        "tier": "family", "host": "host-first", "program": "kernel",
        "line_count": 2, "start_ts": 0.0, "end_ts": 60.0,
        "span_seconds": 60.0, "sample_raw": ["a", "b"], "label": None,
    })
    cells = project_row(finding)
    assert cells[0].key == "first"
    assert cells[0].value == "Jan  1 00:00:00"
    assert cells[1].value == "host-first · kernel · 2 rare lines · 1m"
    text_out = _text([finding])
    html_out = _html_text([finding])
    assert "Jan  1 00:00:00 · host-first" in text_out
    assert "first=" not in text_out
    assert "first" in html_out
    assert html_out.index("first") < html_out.index("host-first")


def test_syslog_needle_stamp_projection_uses_strict_four_arm_gate(
    restore_display_utc,
) -> None:
    set_display_utc(False)
    first_seen = "2026-07-12T21:57:33+00:00"

    def needle(title: str, evidence: dict) -> Finding:
        return _f("syslog", Severity.LOW, title, evidence)

    self_stamped = needle(
        "Jul 12 21:57:33 host-a cron: flat payload",
        {"first_seen": first_seen, "self_stamped": True},
    )
    cells = project_row(self_stamped)
    assert [(cell.key, cell.value, cell.full_width) for cell in cells] == [
        (None, self_stamped.title, True),
    ]

    stamped = needle(
        "bare journal payload",
        {"first_seen": first_seen, "self_stamped": False},
    )
    cells = project_row(stamped)
    assert [(cell.key, cell.value, cell.full_width) for cell in cells] == [
        ("first", "Jul 12 21:57:33", False),
        (None, "bare journal payload", False),
    ]

    no_timestamp = needle(
        "undated journal payload",
        {"first_seen": None, "self_stamped": False},
    )
    cells = project_row(no_timestamp)
    assert [(cell.key, cell.value, cell.full_width) for cell in cells] == [
        (None, no_timestamp.title, True),
    ]

    legacy = needle("legacy producer payload", {"first_seen": first_seen})
    cells = project_row(legacy)
    assert [(cell.key, cell.value, cell.full_width) for cell in cells] == [
        (None, legacy.title, True),
    ]

    text_out = _text([stamped])
    html_out = render_report_html(
        [stamped], _summary([stamped]), verbose_level=0,
        max_findings_per_detector=100,
    )
    assert "Jul 12 21:57:33 · bare journal payload" in text_out
    assert '<th class="col-first">first</th>' in html_out
    assert '<td class="data col-first">Jul 12 21:57:33</td>' in html_out
    assert '<div class="clip">bare journal payload</div>' in html_out


def test_syslog_burst_reboot_label_follows_host_and_timestamp_leads() -> None:
    finding = _f("syslog", Severity.INFO, "host-burst", {
        "tier": "burst", "line_count": 3, "span_seconds": 2.0,
        "start_ts": 0.0, "end_ts": 2.0,
        "program_mix": [["kernel", 3]], "sample_raw": ["a", "b", "c"],
        "label": "rebooted",
    })
    cells = project_row(finding)
    assert [(cell.key, cell.value) for cell in cells] == [
        ("first", "Jan  1 00:00:00"),
        (None, "host-burst · rebooted · 3 rare lines · 2s · mostly kernel"),
    ]

    indeterminate = _f("syslog", Severity.INFO, "host-no-burst-time", {
        "tier": "burst", "line_count": 3, "span_seconds": 2.0,
        "start_ts": None, "end_ts": None,
        "program_mix": [["kernel", 3]], "sample_raw": ["a", "b", "c"],
        "label": "rebooted",
    })
    cells = project_row(indeterminate)
    assert [(cell.key, cell.value) for cell in cells] == [
        (None, "host-no-burst-time · rebooted · 3 rare lines · 2s · mostly kernel"),
    ]
    assert cells[0].full_width is True


def test_syslog_reboot_timestamp_uses_display_formatter_and_null_vanishes(
    restore_display_utc,
) -> None:
    stamped = _f("syslog", Severity.INFO, "host-reboot", {
        "tier": "reboot", "host": "host-reboot",
        "reboot_ts": "2026-06-01T07:08:09+00:00", "label": "rebooted",
    })
    assert [(cell.key, cell.value) for cell in project_row(stamped)] == [
        ("first", "Jun  1 07:08:09"),
        (None, "host-reboot · rebooted"),
    ]

    set_display_utc(True)
    assert [(cell.key, cell.value) for cell in project_row(stamped)] == [
        ("first", "Jun  1 07:08:09 UTC"),
        (None, "host-reboot · rebooted"),
    ]

    indeterminate = _f("syslog", Severity.INFO, "host-unknown", {
        "tier": "reboot", "host": "host-unknown",
        "reboot_ts": None, "label": "rebooted",
    })
    cells = project_row(indeterminate)
    assert [(cell.key, cell.value) for cell in cells] == [
        (None, "host-unknown · rebooted"),
    ]
    assert cells[0].full_width is True
    rendered = _text([indeterminate])
    assert "host-unknown · rebooted" in rendered
    assert "rebooted @" not in rendered


@pytest.mark.parametrize(
    "variant",
    ["syslog_family", "syslog_burst", "syslog_transaction"],
)
def test_syslog_member_fragment_parity_outside_projector(variant: str) -> None:
    finding = _VARIANTS[variant]
    fragments = finding.evidence["member_fragments"]
    text_out = _text([finding])
    html_out = _html_text([finding])
    for fragment in fragments:
        assert fragment in text_out
        assert fragment in html_out


@pytest.mark.parametrize("level", [1, 2])
def test_exfil_pool_member_parity_outside_projector(level: int) -> None:
    finding = _VARIANTS["exfil_pool"]
    text_out = _text([finding], level=level)
    html_out = _html_text([finding], level=level)
    for member in finding.evidence["members"]:
        assert member["dst"] in text_out
        assert member["dst"] in html_out


def test_projection_covers_every_detector_variant() -> None:
    """project_row + section_columns handle every detector/variant without error,
    and produce a stable positional column template (no KeyError / empty grid)."""
    for variant, finding in _VARIANTS.items():
        cells = project_row(finding)
        assert cells, f"{variant}: empty projection"
        # section_columns must not raise and must be positional (len >= row width
        # for a single-row grid, full_width rows excepted).
        sec = Section(None, [finding], 1)
        cols = section_columns(sec)
        if cells[0].full_width:
            assert cols == []  # full-width carries no grid columns
        else:
            assert len(cols) == len(cells)


def test_exfil_projection_keeps_measured_facts_and_restores_transport() -> None:
    from sigwood.outputs._render_model import html_cell_value

    cells = project_row(_VARIANTS["exfil"])
    keyed = {cell.key: cell for cell in cells if cell.key is not None}
    assert keyed["out"].value == "out=1.6 GB"
    assert keyed["transport"].value == "9931/tcp (1.7 GB)"
    assert keyed["sent"].value == "99.99% sent"
    assert keyed["conns"].value == "conns=37"
    assert [cell.key for cell in cells] == [
        None, None, None, "dsts", "out", "sent", "transport", "conns", "span",
    ]
    assert html_cell_value(keyed["out"]) == "1.6 GB"
    assert html_cell_value(keyed["transport"]) == "9931/tcp (1.7 GB)"
    assert html_cell_value(keyed["sent"]) == "99.99%"
    assert html_cell_value(keyed["conns"]) == "37"


def test_dns_renamed_keys_strip_at_singular_counts_on_both_paths() -> None:
    singleton = _f("dns", Severity.MEDIUM, "single.example", {
        "source": "zeek", "label_score": 4.1, "query_count": 1,
        "unique_sources": 1,
    })
    group = _f("dns", Severity.MEDIUM, "group.example", {
        "source": "zeek", "registrable_domain": "group.example",
        "subdomain_count": 1, "max_label_score": 4.1, "min_label_score": 4.1,
        "total_queries": 1, "unique_sources": 1,
    })

    singleton_keyed = {cell.key: cell for cell in project_row(singleton)}
    assert singleton_keyed["entropy"].value == "entropy=4.10"
    assert singleton_keyed["queries"].value == "queries=1"
    assert singleton_keyed["clients"].value == "clients=1"
    assert html_cell_value(singleton_keyed["entropy"]) == "4.10"
    assert html_cell_value(singleton_keyed["queries"]) == "1"
    assert html_cell_value(singleton_keyed["clients"]) == "1"

    group_keyed = {cell.key: cell for cell in project_row(group)}
    assert group_keyed["names"].value == "names=1"
    assert group_keyed["entropy"].value == "entropy=4.10"
    assert group_keyed["queries"].value == "queries=1"
    assert group_keyed["clients"].value == "clients=1"
    assert html_cell_value(group_keyed["names"]) == "1"
    assert html_cell_value(group_keyed["entropy"]) == "4.10"

    range_group = _f("dns", Severity.MEDIUM, "range.example", {
        "source": "zeek", "registrable_domain": "range.example",
        "subdomain_count": 2, "max_label_score": 4.1, "min_label_score": 3.2,
        "total_queries": 2, "unique_sources": 1,
    })
    range_keyed = {cell.key: cell for cell in project_row(range_group)}
    assert range_keyed["entropy"].value == "entropy=4.10-3.20"
    assert html_cell_value(range_keyed["entropy"]) == "4.10-3.20"

    html_out = render_report_html(
        [group, singleton], _summary([group, singleton]),
        verbose_level=0, max_findings_per_detector=100,
    )
    # The header text is the READER label; the class is the machine KEY. They are
    # deliberately different words here - a bare `entropy` header would invite the
    # number to be read as bits of Shannon entropy, which it is not.
    assert '<th class="col-entropy">entropy score</th>' in html_out
    assert '<td class="data">4.10</td>' in html_out
    assert "entropy=4.10" not in html_out


def test_exfil_transport_is_whole_group_optional_and_share_boundary_is_exact() -> None:
    multi = _f("exfil", Severity.MEDIUM, "x", {
        "src": "192.0.2.1", "dst": "198.51.100.1",
        "orig_bytes_total": 1_900_000_000, "orig_share": 1.0,
        "connection_count": 2,
        "port_mix": "443/tcp (1.5 GB), 8443/tcp (400 MB)",
    })
    multi_keyed = {cell.key: cell for cell in project_row(multi)}
    assert multi_keyed["transport"].value == "443/tcp (1.5 GB), 8443/tcp (400 MB)"
    assert multi_keyed["sent"].value == "100.00% sent"

    blank = _VARIANTS["exfil_pool"]
    blank_transport = next(
        col for col in section_columns(Section(None, [blank], 1))
        if col.key == "transport"
    )
    assert blank_transport.optional is True
    assert blank_transport.all_empty is True

    mixed_transport = next(
        col for col in section_columns(Section(None, [blank, multi], 2))
        if col.key == "transport"
    )
    assert mixed_transport.all_empty is False


def test_scan_outcome_copy_is_bound_to_the_exact_six_state_set() -> None:
    assert SCAN_STATES == {"S0", "REJ", "RSTO", "RSTR", "SH", "OTH"}
    cells = project_row(_VARIANTS["scan_vertical"])
    assert [cell.key for cell in cells] == [
        None, "middle", "type", "outcome", "metric",
    ]
    keyed = {cell.key: cell for cell in cells}
    assert keyed["outcome"].value == "91% no normal close seen"

    text_out = _text([_VARIANTS["scan_vertical"]])
    html_out = render_report_html(
        [_VARIANTS["scan_vertical"]],
        _summary([_VARIANTS["scan_vertical"]]),
        verbose_level=0,
        max_findings_per_detector=100,
    )
    assert text_out.index("192.0.2.231") < text_out.index("vertical")
    assert html_out.index("192.0.2.231") < html_out.index(">vertical</td>")


def test_dns_scan_summary_names_the_visible_review_object() -> None:
    cells = project_row(_VARIANTS["dns_scan_summary"])
    assert [cell.value for cell in cells] == [
        "dense-cluster scan surfaced 2 high-entropy clusters (3217 queries) - "
        "review the dense-cluster findings above before allowlisting"
    ]
