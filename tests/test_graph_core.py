"""Payload and budget contracts for the conn and DNS graph builders."""

from __future__ import annotations

import math

import numpy as np
import pandas as pd
import pytest

from sigwood.common.errors import GraphEmpty
from sigwood.graph import _core
from sigwood.graph._core import (
    GRAPH_MAX_FLOWS,
    _assert_budgets,
    build_payload,
    pick_bin_seconds,
    validate_config,
)
from sigwood.graph.conn import build as build_conn
from sigwood.graph.dns import build as build_dns


def _config(**overrides: object) -> dict[str, object]:
    return validate_config(overrides)


def _conn_frame(**overrides: object) -> pd.DataFrame:
    columns: dict[str, object] = {
        "ts": [0.0, 1.0],
        "src": ["192.0.2.10", "192.0.2.11"],
        "dst": ["198.51.100.10", "198.51.100.11"],
        "port": [443, 53],
        "proto": ["tcp", "udp"],
        "bytes": [10, 20],
    }
    columns.update(overrides)
    return pd.DataFrame(columns)


def _grouped(flow_count: int) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "s": [f"s{index}" for index in range(flow_count)],
            "d": [f"d{index}" for index in range(flow_count)],
            "v": ["tcp" for _ in range(flow_count)],
            "bin": [0 for _ in range(flow_count)],
            "b": [0 for _ in range(flow_count)],
            "c": [1 for _ in range(flow_count)],
        }
    )


def test_validate_graph_config_merges_defaults_and_rejects_invalid_scalars() -> None:
    assert validate_config({"target_bins": 1, "domain_level": "tld"}) == {
        "target_bins": 1,
        "top_hosts": 24,
        "top_services": 12,
        "domain_level": "tld",
    }

    with pytest.raises(ValueError, match=r"\[graph\] must be a table"):
        validate_config([])

    for key, value in (
        ("target_bins", True),
        ("target_bins", "200"),
        ("target_bins", 0),
        ("target_bins", 20_001),
        ("top_hosts", False),
        ("top_hosts", 501),
        ("top_services", 0),
        ("domain_level", "host"),
    ):
        with pytest.raises(ValueError):
            validate_config({key: value})


@pytest.mark.parametrize(
    ("builder", "frame", "missing"),
    [
        (build_conn, _conn_frame(dst=["198.51.100.10", "198.51.100.11"]), "bytes"),
        (
            build_dns,
            pd.DataFrame(
                {
                    "ts": [0.0],
                    "src": ["192.0.2.10"],
                    "qtype": [1],
                }
            ),
            "query",
        ),
    ],
)
def test_builders_report_missing_raw_fields_as_controlled_value_errors(
    builder, frame: pd.DataFrame, missing: str
) -> None:
    if builder is build_conn:
        frame = frame.drop(columns=[missing])

    with pytest.raises(ValueError, match=rf"\.log fields not found: {missing}"):
        builder(frame, config=_config(), source_label="sample.log")


def test_graph_empty_covers_no_timestamped_rows_and_post_preparation_empty_dns() -> None:
    with pytest.raises(GraphEmpty) as no_timestamps:
        build_conn(
            _conn_frame(ts=[np.nan, math.inf]),
            config=_config(),
            source_label="conn\x1b.log",
        )
    assert no_timestamps.value.kind == "conn"
    assert no_timestamps.value.source_label == "conn.log"
    assert no_timestamps.value.reason == "no timestamped rows"

    with pytest.raises(GraphEmpty) as no_queries:
        build_dns(
            pd.DataFrame(
                {
                    "ts": [0.0, 1.0],
                    "src": ["192.0.2.10", "192.0.2.11"],
                    "query": [None, np.nan],
                }
            ),
            config=_config(),
            source_label="dns.log",
        )
    assert no_queries.value.kind == "dns"
    assert no_queries.value.source_label == "dns.log"
    assert no_queries.value.reason == "no query rows"


def test_conn_payload_keeps_null_metrics_as_zero_and_collapses_icmp() -> None:
    payload = build_conn(
        _conn_frame(
            port=[443, 8],
            proto=["TCP", "ICMP"],
            bytes=[12, None],
        ),
        config=_config(),
        source_label="conn.log",
        default_window_note="default 7d window applied",
        display_utc=True,
    )

    assert payload["meta"] | {"generated_utc": "ignored"} == {
        "source": "conn.log",
        "rows": 2,
        "t0": 0.0,
        "t1": 1.0,
        "bin_seconds": 1,
        "bins": 2,
        "distinct_hosts": 4,
        "distinct_services": 2,
        "generated_utc": "ignored",
        "generator": payload["meta"]["generator"],
        "display_utc": True,
        "default_window_note": "default 7d window applied",
        "kind": "conn",
        "single_metric": False,
        "rows_label": "conns",
        "hosts_label": "hosts seen",
        "mid_label": "services",
        "mid_singular": "service",
        "metric_note": "orig bytes",
    }
    assert payload["svcNodes"] == ["443/tcp", "icmp"]
    assert payload["totB"] == [12, 0]
    assert payload["totC"] == [1, 1]
    assert payload["flows"][1]["b"] == [1, 0]
    assert payload["flows"][1]["c"] == [1, 1]


def test_core_discards_nonfinite_timestamps_but_keeps_zero_metric_rows() -> None:
    payload = build_conn(
        _conn_frame(
            ts=[10.0, 10.0, math.inf, np.nan],
            src=["192.0.2.10"] * 4,
            dst=["198.51.100.10"] * 4,
            port=[443] * 4,
            proto=["tcp"] * 4,
            bytes=[None, math.inf, 99, 99],
        ),
        config=_config(target_bins=1),
        source_label="conn.log",
    )

    assert payload["meta"]["rows"] == 2
    assert payload["meta"]["bins"] == 1
    assert payload["totB"] == [0]
    assert payload["totC"] == [2]
    assert payload["flows"] == [{"s": 0, "d": 0, "v": 0, "b": [0, 0], "c": [0, 2]}]


def test_clean_labels_coalesce_before_grouping_and_ranking() -> None:
    payload = build_conn(
        _conn_frame(
            ts=[0.0, 0.0],
            src=["192.0.2.10\x1b", "192.0.2.10"],
            dst=["198.51.100.10", "198.51.100.10\x7f"],
            port=[443, 443],
            proto=["tcp", "tcp\x80"],
            bytes=[1, 2],
        ),
        config=_config(),
        source_label="conn.log",
    )

    assert [node["id"] for node in payload["srcNodes"]] == ["192.0.2.10"]
    assert [node["id"] for node in payload["dstNodes"]] == ["198.51.100.10"]
    assert payload["svcNodes"] == ["443/tcp"]
    assert payload["flows"] == [{"s": 0, "d": 0, "v": 0, "b": [0, 3], "c": [0, 2]}]


def test_dns_uses_qtype_fallback_then_resolver_and_rolls_domains() -> None:
    qtype_payload = build_dns(
        pd.DataFrame(
            {
                "ts": [0.0, 1.0],
                "src": ["192.0.2.10", "192.0.2.11"],
                "query": ["www.example.com.", "api.example.com."],
                "qtype": [1, 99],
            }
        ),
        config=_config(domain_level="domain"),
        source_label="dns.log",
    )
    assert qtype_payload["meta"]["single_metric"] is True
    assert qtype_payload["meta"]["mid_label"] == "qtypes"
    assert qtype_payload["svcNodes"] == ["99", "A"]
    assert [node["id"] for node in qtype_payload["dstNodes"]] == ["example.com"]
    assert qtype_payload["totB"] == [1, 1]
    assert qtype_payload["totC"] == [1, 1]

    resolver_payload = build_dns(
        pd.DataFrame(
            {
                "ts": [0.0, 1.0],
                "src": ["192.0.2.10", "192.0.2.11"],
                "query": ["one.example.co.uk.", "two.example.co.uk."],
                "qtype": [1, 28],
                "resolver": ["198.51.100.53", None],
            }
        ),
        config=_config(domain_level="tld"),
        source_label="dns.log",
    )
    assert resolver_payload["meta"]["mid_label"] == "resolvers"
    assert resolver_payload["svcNodes"] == ["(unknown)", "198.51.100.53"]
    assert [node["id"] for node in resolver_payload["dstNodes"]] == ["co.uk"]


def test_top_folding_keeps_ranked_nodes_orders_other_last_and_preserves_census() -> None:
    payload = build_conn(
        _conn_frame(
            ts=[0.0, 1.0, 2.0],
            src=["192.0.2.1", "192.0.2.2", "192.0.2.3"],
            dst=["198.51.100.1", "198.51.100.2", "198.51.100.2"],
            port=[80, 443, 443],
            proto=["tcp", "tcp", "tcp"],
            bytes=[10, 5, 5],
        ),
        config=_config(top_hosts=1, top_services=1),
        source_label="conn.log",
    )

    assert [node["id"] for node in payload["srcNodes"]] == ["192.0.2.1", "(other)"]
    assert [node["id"] for node in payload["dstNodes"]] == ["198.51.100.2", "(other)"]
    assert payload["svcNodes"] == ["443/tcp", "(other)"]
    assert payload["meta"]["distinct_hosts"] == 5
    assert payload["meta"]["distinct_services"] == 2
    assert payload["hostsSeen"] == [2, 4, 5]
    assert payload["flows"][0]["b"] == [0, 10]


def test_bin_picker_uses_a_week_multiple_beyond_its_largest_nice_tier() -> None:
    assert pick_bin_seconds(604_800, 1) == 1_209_600
    assert pick_bin_seconds(604_801, 1) == 1_209_600
    assert pick_bin_seconds(0, 1) == 5


def test_flow_budget_is_independent_of_the_slider_and_pair_budgets() -> None:
    with pytest.raises(ValueError, match="graph too dense"):
        _assert_budgets(_grouped(GRAPH_MAX_FLOWS + 1), bins=1)


def test_smooth_budget_is_independent_of_flow_and_pair_budgets() -> None:
    # 576 flows/1,440 bins are just inside the interaction ceiling; adding
    # one otherwise-identical flow crosses it without touching other limits.
    assert _core.GRAPH_MAX_SMOOTH_OPS == 400_000_000
    _assert_budgets(_grouped(576), bins=1_440)
    with pytest.raises(ValueError, match="graph too dense"):
        _assert_budgets(_grouped(577), bins=1_440)


def test_smooth_budget_uses_the_player_half_up_slider_rounding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A .5 slider tie matches JavaScript Math.round rather than banker rounding."""
    assert _core._slider_radius(318) == 27
    # This threshold sits between the work produced by radius 26 and 27.
    monkeypatch.setattr(_core, "GRAPH_MAX_SMOOTH_OPS", 130_000_000)
    with pytest.raises(ValueError, match="graph too dense"):
        _assert_budgets(_grouped(3_856), bins=318)


def test_pair_budget_counts_zero_metric_series_before_pair_lists(monkeypatch) -> None:
    # Keep the production threshold assertion visible while lowering only the
    # test seam. Two all-zero bin rows emit four values: b and c pairs each.
    assert _core.GRAPH_MAX_PAYLOAD_PAIRS == 1_500_000
    monkeypatch.setattr(_core, "GRAPH_MAX_PAYLOAD_PAIRS", 2)
    monkeypatch.setattr(_core, "GRAPH_MAX_SMOOTH_OPS", 10**12)

    with pytest.raises(ValueError, match="graph too dense"):
        build_payload(
            pd.DataFrame(
                {
                    "ts": [0.0, 1.0],
                    "src": ["192.0.2.10", "192.0.2.10"],
                    "dst": ["198.51.100.10", "198.51.100.10"],
                    "svc": ["dns", "dns"],
                    "metric": [0, 0],
                }
            ),
            kind="test",
            source_label="test.log",
            config=_config(),
            meta={},
            default_window_note=None,
        )


def test_explicit_one_bin_target_keeps_an_exact_endpoint_span_in_one_bin() -> None:
    payload = build_conn(
        _conn_frame(
            ts=[0.0, 1.0],
            src=["192.0.2.10", "192.0.2.10"],
            dst=["198.51.100.10", "198.51.100.10"],
            port=[443, 443],
            proto=["tcp", "tcp"],
            bytes=[1, 1],
        ),
        config=_config(target_bins=1),
        source_label="conn.log",
    )

    assert payload["meta"]["bins"] == 1
    assert payload["totC"] == [2]
    _assert_budgets(_grouped(GRAPH_MAX_FLOWS), bins=1)


def test_core_drops_out_of_range_timestamps_and_rejects_unsafe_metrics() -> None:
    """Finite host-language magnitudes cannot create an invalid player payload."""
    with pytest.raises(GraphEmpty, match="no timestamped rows"):
        build_conn(
            _conn_frame(ts=[-1e308, 1e308]),
            config=_config(),
            source_label="conn.log",
        )

    with pytest.raises(ValueError, match="metric values are too large"):
        build_conn(
            _conn_frame(bytes=[1e308, 1]),
            config=_config(),
            source_label="conn.log",
        )

    # A player filter can select only positive flows, so signed net totals do
    # not prove Float32 safety. The absolute per-bin contribution is bounded.
    with pytest.raises(ValueError, match="metric values are too large"):
        build_payload(
            pd.DataFrame({
                "ts": [0.0, 0.0, 0.0],
                "src": ["192.0.2.10", "192.0.2.11", "192.0.2.12"],
                "dst": ["198.51.100.10"] * 3,
                "svc": ["dns"] * 3,
                "metric": [3e38, 3e38, -3e38],
            }),
            kind="test", source_label="test.log", config=_config(),
            meta={}, default_window_note=None,
        )


def test_build_payload_does_not_mutate_caller_metadata() -> None:
    """The shared payload seam remains pure for programmatic graph builders."""
    meta = {"display_utc": True, "kind": "test"}
    frame = pd.DataFrame({
        "ts": [0.0],
        "src": ["192.0.2.10"],
        "dst": ["198.51.100.10"],
        "svc": ["dns"],
        "metric": [1],
    })

    payload = build_payload(
        frame, kind="test", source_label="test.log", config=_config(),
        meta=meta, default_window_note=None,
    )

    assert meta == {"display_utc": True, "kind": "test"}
    assert payload["meta"]["display_utc"] is True
    _assert_budgets(_grouped(GRAPH_MAX_FLOWS), bins=1)


def test_graph_builders_contain_oversized_label_string_conversion() -> None:
    """Hostile numeric labels degrade safely before they reach script data."""
    too_large_to_render = 10 ** 5_000

    conn_frame = _conn_frame()
    conn_frame["proto"] = pd.Series(
        [too_large_to_render, "tcp"], dtype=object,
    )
    conn_payload = build_conn(
        conn_frame,
        config=_config(),
        source_label="conn.log",
    )
    assert "443/(unknown)" in conn_payload["svcNodes"]

    dns_frame = pd.DataFrame({
        "ts": [0.0],
        "src": ["192.0.2.10"],
        "query": ["example.test"],
    })
    dns_frame["resolver"] = pd.Series([too_large_to_render], dtype=object)
    dns_payload = build_dns(
        dns_frame,
        config=_config(),
        source_label="dns.log",
    )
    assert dns_payload["svcNodes"] == ["(unknown)"]
