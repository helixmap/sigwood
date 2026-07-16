"""Payload and budget contracts for the conn and DNS graph builders."""

from __future__ import annotations

import json
import math
import weakref

import numpy as np
import pandas as pd
import pytest

from sigwood.common.display import set_display_utc
from sigwood.common.errors import GraphEmpty
from sigwood.graph import _core
from sigwood.graph._core import (
    GRAPH_MAX_SMOOTH_OPS,
    _format_degrade_note,
    attach_hunt_hint,
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


def _timestamp_frame(counts: dict[int, int]) -> pd.DataFrame:
    """Build a compact synthetic row population keyed by one-second bin."""
    return pd.DataFrame({
        "ts": np.concatenate([
            np.full(count, float(bin_index))
            for bin_index, count in counts.items()
        ]),
    })


def test_validate_graph_config_merges_defaults_and_rejects_invalid_scalars() -> None:
    assert validate_config({"target_bins": 1, "domain_level": "tld"}) == {
        "target_bins": 1,
        "top_hosts": 30,
        "top_services": 16,
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
        (build_conn, _conn_frame(), "dst"),
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


@pytest.mark.parametrize("missing_service", ["port", "proto"])
def test_conn_missing_optional_columns_degrade_to_count_only_unknown_service(
    missing_service: str,
) -> None:
    frame = _conn_frame().drop(columns=["bytes", missing_service])

    payload = build_conn(
        frame, config=_config(), source_label="conn.log",
    )

    assert payload["meta"]["single_metric"] is True
    assert payload["meta"]["missing_bytes"] is True
    assert payload["svcNodes"] == ["unknown"]
    assert payload["totB"] == [1, 1]
    assert payload["totC"] == [1, 1]
    assert _format_degrade_note(payload["meta"]) == (
        "conn.log has no byte counts; showing connection counts only"
    )


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
        "weighted": False,
        "hunt_hint": None,
        "kind": "conn",
        "single_metric": False,
        "rows_label": "conns",
        "hosts_label": "hosts seen",
        "mid_label": "services",
        "mid_singular": "service",
        "metric_note": None,
        "missing_bytes": False,
        "trim_noun_singular": "connection",
        "trim_noun_plural": "connections",
        "requested_bin_seconds": 1,
        "requested_top_hosts": 30,
        "requested_top_services": 16,
        "effective_top_hosts": 30,
        "effective_top_services": 16,
        "natural_radius": 6,
        "max_radius": 6,
        "altered_metric_cells": 0,
        "trimmed_leading": 0,
        "trimmed_trailing": 0,
        "trim_lead_epoch": None,
        "trim_trail_epoch": None,
        "date_window_widened": False,
        "degrade_note": None,
    }
    assert payload["svcNodes"] == ["443/tcp", "icmp"]
    assert payload["totB"] == [12, 0]
    assert payload["totC"] == [1, 1]
    assert payload["flows"][1]["b"] == [1, 0]
    assert payload["flows"][1]["c"] == [1, 1]


def test_nice_bin_ladder_preserves_nested_successors_and_one_bin_terminal() -> None:
    """Spread-fragment descent relies on divisible nonterminal grid widths."""
    assert all(
        successor % current == 0
        for current, successor in zip(
            _core._NICE_BIN_SECONDS, _core._NICE_BIN_SECONDS[1:],
        )
    )
    terminal = pick_bin_seconds(8 * 86_400, 1)
    assert _core._next_bin_seconds(_core._NICE_BIN_SECONDS[-1], 8 * 86_400) == terminal
    assert _core._next_bin_seconds(terminal, 8 * 86_400) is None


@pytest.mark.parametrize(
    "duration",
    [None, [None, None], [0, 0], [-1, -2], [math.nan, math.inf]],
)
def test_conn_duration_activation_false_keeps_the_point_contract(
    duration: object,
) -> None:
    frame = _conn_frame()
    if duration is not None:
        frame["duration"] = duration

    payload = build_conn(frame, config=_config(), source_label="conn.log")

    assert "bands_active" not in payload["meta"]
    assert payload["meta"]["rows_label"] == "conns"
    assert payload["meta"]["metric_note"] is None
    assert payload["totB"] == [10, 20]


def test_conn_duration_activation_is_same_row_and_contains_oversized_values() -> None:
    crossed = build_conn(
        _conn_frame(bytes=[100, 0], duration=[0, 3_600]),
        config=_config(),
        source_label="conn.log",
    )
    oversized = build_conn(
        _conn_frame(duration=pd.Series([10 ** 5_000, 0], dtype=object)),
        config=_config(),
        source_label="conn.log",
    )

    for payload in (crossed, oversized):
        assert "bands_active" not in payload["meta"]
        assert payload["meta"]["rows_label"] == "conns"
        assert payload["meta"]["metric_note"] is None


def test_mixed_oversized_byte_value_zeros_silently_but_preserves_counts() -> None:
    """Accepted trade: one unrenderable byte value is not a lost conn row."""
    payload = build_conn(
        _conn_frame(
            bytes=pd.Series([10 ** 400, 1_000], dtype=object),
            duration=[60, 0],
        ),
        config=_config(),
        source_label="conn.log",
    )

    assert payload["meta"]["missing_bytes"] is False
    assert payload["meta"]["single_metric"] is False
    assert payload["meta"]["altered_metric_cells"] == 0
    assert "bands_active" not in payload["meta"]
    assert sum(payload["totB"]) == 1_000
    assert sum(payload["totC"]) == 2


@pytest.mark.parametrize("values", [[None, None], [0, 0], [-1, -2]])
def test_conn_nonpositive_byte_mass_uses_the_count_only_fallback(
    values: list[object],
) -> None:
    payload = build_conn(
        _conn_frame(bytes=values, duration=[60, 60]),
        config=_config(),
        source_label="conn.log",
    )

    assert payload["meta"]["single_metric"] is True
    assert payload["meta"]["missing_bytes"] is True
    assert "bands_active" not in payload["meta"]
    assert payload["totB"] == [1, 1]
    assert payload["totC"] == [1, 1]


def test_duration_bands_spread_bytes_but_keep_counts_at_starts() -> None:
    payload = build_conn(
        _conn_frame(
            ts=[0.0, 120.0],
            src=["192.0.2.10", "192.0.2.10"],
            dst=["198.51.100.10", "198.51.100.10"],
            port=[443, 443],
            proto=["tcp", "tcp"],
            bytes=[120, 0],
            duration=[120, 0],
        ),
        config=_config(target_bins=4),
        source_label="conn.log",
    )

    assert payload["meta"]["bands_active"] is True
    assert payload["meta"]["rows_label"] == "conn starts"
    assert payload["meta"]["bin_seconds"] == 60
    assert payload["totB"] == [60, 60, 0]
    assert payload["totC"] == [1, 0, 1]
    assert sum(payload["totB"]) == 120
    assert sum(payload["totC"]) == payload["meta"]["rows"]
    assert "band_loss" not in payload["meta"]


def test_duration_band_one_bin_partial_uses_overlap_and_discloses_loss(
    restore_display_utc,
) -> None:
    set_display_utc(True)
    payload = build_conn(
        _conn_frame(
            ts=[0.0, 50.0],
            src=["192.0.2.10", "192.0.2.10"],
            dst=["198.51.100.10", "198.51.100.10"],
            port=[443, 443],
            proto=["tcp", "tcp"],
            bytes=[0, 100],
            duration=[0, 20],
        ),
        config=_config(target_bins=2),
        source_label="conn.log",
    )

    assert payload["meta"]["bins"] == 1
    assert payload["totB"] == [50]
    assert payload["totC"] == [2]
    assert payload["meta"]["band_loss"] == {
        "lead_conns": 0,
        "lead_bytes": 0,
        "trail_conns": 1,
        "trail_bytes": 50,
    }
    assert payload["meta"]["band_loss_note"] == (
        "1 connection continues past the retained window end; "
        "50 B not shown after 1970-01-01 00:01 UTC"
    )


def test_duration_fraction_is_computed_before_extreme_metric_multiplication() -> None:
    payload = build_conn(
        _conn_frame(
            ts=[0.0, 50.0],
            bytes=[0, _core._FLOAT32_MAX],
            duration=[0, 1e308],
        ),
        config=_config(target_bins=2),
        source_label="conn.log",
    )

    assert payload["meta"]["bands_active"] is True
    assert payload["meta"]["band_loss"]["trail_bytes"] > 0
    assert sum(payload["totC"]) == 2
    json.dumps(payload, allow_nan=False)


def test_fragment_budget_coarsens_only_positive_multi_bin_mass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _core.GRAPH_MAX_SPREAD_FRAGMENTS == 3_000_000
    monkeypatch.setattr(_core, "GRAPH_MAX_SPREAD_FRAGMENTS", 2)
    payload = build_conn(
        _conn_frame(
            ts=[0.0, 9.0],
            src=["192.0.2.10", "192.0.2.10"],
            dst=["198.51.100.10", "198.51.100.10"],
            port=[443, 443],
            proto=["tcp", "tcp"],
            bytes=[9, 0],
            duration=[9, 0],
        ),
        config=_config(target_bins=20),
        source_label="conn.log",
    )

    assert payload["meta"]["requested_bin_seconds"] == 1
    assert payload["meta"]["bin_seconds"] == 5
    assert payload["totB"] == [5, 4]
    assert payload["totC"] == [1, 1]
    assert "binned to 5s" in (_format_degrade_note(payload["meta"]) or "")

    zero_mass = _conn_frame(
        ts=[0.0, 9.0, 9.0],
        src=["192.0.2.10"] * 3,
        dst=["198.51.100.10"] * 3,
        port=[443] * 3,
        proto=["tcp"] * 3,
        bytes=[0, 0, 1],
        duration=[10_000, 10_000, 0.5],
    )
    unchanged = build_conn(
        zero_mass,
        config=_config(target_bins=20),
        source_label="conn.log",
    )
    assert unchanged["meta"]["requested_bin_seconds"] == 1
    assert unchanged["meta"]["bin_seconds"] == 1
    assert sum(unchanged["totC"]) == 3

    monkeypatch.setattr(_core, "GRAPH_MAX_SPREAD_FRAGMENTS", 4)
    just_inside = build_conn(
        _conn_frame(
            ts=[0.0, 5.0],
            bytes=[4, 0],
            duration=[4, 0],
        ),
        config=_config(target_bins=20),
        source_label="conn.log",
    )
    just_outside = build_conn(
        _conn_frame(
            ts=[0.0, 5.0],
            bytes=[5, 0],
            duration=[5, 0],
        ),
        config=_config(target_bins=20),
        source_label="conn.log",
    )
    assert just_inside["meta"]["bin_seconds"] == 1
    assert just_outside["meta"]["bin_seconds"] == 5


def test_duration_trim_keeps_straddler_clamps_count_and_scopes_model_note(
    restore_display_utc,
) -> None:
    dense_ts = [
        float(bin_index)
        for bin_index in range(6, 14)
        for _ in range(2_000)
    ]
    frame = pd.DataFrame({
        "ts": [0.0, *dense_ts],
        "src": ["192.0.2.250", *(["192.0.2.10"] * 16_000)],
        "dst": ["198.51.100.250", *(["198.51.100.10"] * 16_000)],
        "port": [443] * 16_001,
        "proto": ["tcp"] * 16_001,
        "bytes": [100, *([1] * 16_000)],
        "duration": [100, *([1] * 16_000)],
    })
    frame.index = [index // 2 for index in range(len(frame))]
    set_display_utc(True)

    payload = build_conn(
        frame,
        config=_config(target_bins=20_000),
        source_label="conn.log",
        trim_sparse_edges=True,
    )

    assert payload["meta"]["t0"] == 6.0
    assert payload["meta"]["trimmed_leading"] == 0
    assert payload["meta"]["retained_straddlers"] == 1
    assert payload["meta"]["straddler_note"] == (
        "1 connection that began before the retained window is drawn within it "
        "and counted at its edge"
    )
    assert payload["meta"]["band_loss"] == {
        "lead_conns": 1,
        "lead_bytes": 6,
        "trail_conns": 1,
        "trail_bytes": 86,
    }
    assert payload["meta"]["metric_note"] == (
        "bytes drawn at a constant rate across each connection's recorded duration; "
        "connection counts stay at recorded starts; retained pre-window connections "
        "count at the window edge"
    )
    assert sum(payload["totC"]) == payload["meta"]["rows"] == 16_001
    assert all(
        bin_index >= 0
        for flow in payload["flows"]
        for bin_index in flow["c"][::2]
    )


def test_duration_trim_drops_zero_overlap_boundary_without_a_false_start() -> None:
    dense_ts = [
        float(bin_index)
        for bin_index in range(6, 14)
        for _ in range(2_000)
    ]
    frame = pd.DataFrame({
        "ts": [0.0, *dense_ts],
        "src": ["192.0.2.250", *(["192.0.2.10"] * 16_000)],
        "dst": ["198.51.100.250", *(["198.51.100.10"] * 16_000)],
        "port": [443] * 16_001,
        "proto": ["tcp"] * 16_001,
        "bytes": [6, *([1] * 16_000)],
        "duration": [6, *([1] * 16_000)],
    })

    payload = build_conn(
        frame,
        config=_config(target_bins=20_000),
        source_label="conn.log",
        trim_sparse_edges=True,
    )

    assert payload["meta"]["trimmed_leading"] == 1
    assert "retained_straddlers" not in payload["meta"]
    assert payload["meta"]["rows"] == 16_000
    assert sum(payload["totC"]) == 16_000


def test_descent_releases_prior_basis_and_keeps_measurements_scalar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_core, "GRAPH_MAX_PAYLOAD_PAIRS", 4)
    monkeypatch.setattr(_core, "GRAPH_MAX_SMOOTH_OPS", 10**12)
    actual_build_basis = _core._build_raw_basis
    actual_measure = _core._measure_basis
    prior_basis: weakref.ReferenceType[object] | None = None
    builds = 0
    measurements = 0

    def tracked_build(*args, **kwargs):
        nonlocal prior_basis, builds
        if prior_basis is not None:
            assert prior_basis() is None
        basis = actual_build_basis(*args, **kwargs)
        prior_basis = weakref.ref(basis)
        builds += 1
        return basis

    def tracked_measure(*args, **kwargs):
        nonlocal measurements
        measure = actual_measure(*args, **kwargs)
        assert all(
            not isinstance(value, (pd.DataFrame, np.ndarray))
            for value in vars(measure).values()
        )
        measurements += 1
        return measure

    monkeypatch.setattr(_core, "_build_raw_basis", tracked_build)
    monkeypatch.setattr(_core, "_measure_basis", tracked_measure)
    frame = pd.DataFrame({
        "ts": [float(index) for index in range(10)],
        "src": ["192.0.2.10"] * 10,
        "dst": ["198.51.100.10"] * 10,
        "svc": ["dns"] * 10,
        "metric": [0] * 10,
    })

    payload = build_payload(
        frame,
        kind="test",
        source_label="test.log",
        config=_config(target_bins=20),
        meta={"kind": "test"},
        default_window_note=None,
    )

    assert builds >= 2
    assert measurements >= builds
    assert payload["meta"]["bin_seconds"] == 5


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
    assert qtype_payload["meta"]["metric_note"] == "rolled to registered domain"
    assert qtype_payload["meta"]["weighted"] is False
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
    assert resolver_payload["meta"]["metric_note"] == "rolled to public suffix"
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


def test_sparse_edge_trim_matches_the_182_row_axis_decompression_shape() -> None:
    tail = {index: 9 + (index < 2) for index in range(20)}
    dense = {index: 2_300 for index in range(32, 120)}
    frame = _timestamp_frame({**tail, **dense})

    result = _core._trim_sparse_edges(
        frame, t0=0.0, t1=119.0, bin_seconds=1,
    )

    assert result.trimmed_leading == 182
    assert result.trimmed_trailing == 0
    assert result.lead_boundary_epoch == 32.0
    assert result.trail_boundary_epoch is None
    assert len(result.frame) == 202_400
    assert float(result.frame["ts"].min()) == 32.0
    assert float(result.frame["ts"].max()) == 119.0
    assert (119.0 - 32.0) / (119.0 - 0.0) == pytest.approx(0.731, abs=0.001)


@pytest.mark.parametrize(
    ("dense_start", "trimmed"),
    [(5, 0), (6, 1)],
)
def test_sparse_edge_trim_uses_axis_distance_for_a_singleton(
    dense_start: int, trimmed: int,
) -> None:
    counts = {0: 1, **{
        index: 2_000 for index in range(dense_start, dense_start + 8)
    }}
    frame = _timestamp_frame(counts)

    result = _core._trim_sparse_edges(
        frame,
        t0=0.0,
        t1=float(dense_start + 7),
        bin_seconds=1,
    )

    assert result.trimmed_leading == trimmed
    assert len(result.frame) == len(frame) - trimmed


@pytest.mark.parametrize(
    "counts",
    [
        {index: 100 for index in range(7)},
        {index: 100 for index in range(10)},
        {
            **{index: 40 for index in range(10)},
            **{index: 1_000 for index in range(10, 18)},
        },
        {
            **{index: 11 for index in range(6)},
            **{index: 1_250 for index in range(6, 14)},
        },
        {
            **{index: 1_000 for index in range(8)},
            **{index: 1 for index in range(8, 20)},
            **{index: 1_000 for index in range(20, 28)},
        },
    ],
)
def test_sparse_edge_trim_noops_for_weak_or_interior_shapes(
    counts: dict[int, int],
) -> None:
    frame = _timestamp_frame(counts)

    result = _core._trim_sparse_edges(
        frame,
        t0=float(min(counts)),
        t1=float(max(counts)),
        bin_seconds=1,
    )

    assert result.frame is frame
    assert result.trimmed_leading == 0
    assert result.trimmed_trailing == 0


def test_sparse_edge_trim_can_remove_both_outer_edges() -> None:
    counts = {
        0: 1,
        **{index: 2_000 for index in range(10, 21)},
        30: 1,
    }
    frame = _timestamp_frame(counts)

    result = _core._trim_sparse_edges(
        frame, t0=0.0, t1=30.0, bin_seconds=1,
    )

    assert result.trimmed_leading == 1
    assert result.trimmed_trailing == 1
    assert result.lead_boundary_epoch == 10.0
    assert result.trail_boundary_epoch == 20.0
    assert len(result.frame) == 22_000


def test_sparse_edge_trim_uses_a_positional_mask_with_duplicate_indexes() -> None:
    frame = _timestamp_frame({0: 1, **{index: 2_000 for index in range(6, 14)}})
    frame.index = [index // 2 for index in range(len(frame))]

    result = _core._trim_sparse_edges(
        frame, t0=0.0, t1=13.0, bin_seconds=1,
    )

    assert result.trimmed_leading == 1
    assert len(result.frame) == 16_000
    assert float(result.frame["ts"].min()) == 6.0


def test_sparse_edge_trim_precedes_ranking_and_discloses_same_minute_truthfully(
    restore_display_utc,
) -> None:
    dense_timestamps = [
        float(bin_index)
        for bin_index in range(6, 14)
        for _ in range(2_000)
    ]
    frame = pd.DataFrame({
        "ts": [0.0, *dense_timestamps],
        "src": ["192.0.2.250", *(["192.0.2.10"] * 16_000)],
        "dst": ["198.51.100.250", *(["198.51.100.10"] * 16_000)],
        "svc": ["tail", *(["dns"] * 16_000)],
        "metric": [1_000_000_000, *([1] * 16_000)],
    })
    meta = {
        "kind": "test",
        "trim_noun_singular": "connection",
        "trim_noun_plural": "connections",
    }

    payload = build_payload(
        frame,
        kind="test",
        source_label="test.log",
        config=_config(target_bins=20_000, top_hosts=1, top_services=1),
        meta=meta,
        default_window_note=None,
        trim_sparse_edges=True,
    )

    assert meta == {
        "kind": "test",
        "trim_noun_singular": "connection",
        "trim_noun_plural": "connections",
    }
    assert payload["meta"]["rows"] == 16_000
    assert payload["meta"]["t0"] == 6.0
    assert payload["meta"]["t1"] == 13.0
    assert payload["meta"]["trimmed_leading"] == 1
    assert payload["meta"]["trim_lead_epoch"] == 6.0
    assert "192.0.2.250" not in [node["id"] for node in payload["srcNodes"]]
    assert "tail" not in payload["svcNodes"]

    set_display_utc(True)
    assert _format_degrade_note(payload["meta"]) == (
        "trimmed 1 connection before the retained window to focus the timeline "
        "(window begins 1970-01-01 00:00 UTC)"
    )

    evidence_window = build_payload(
        frame,
        kind="test",
        source_label="test.log",
        config=_config(target_bins=20_000),
        meta=meta,
        default_window_note=None,
        window=(0.0, 13.0),
        trim_sparse_edges=True,
    )
    assert evidence_window["meta"]["rows"] == 16_001
    assert evidence_window["meta"]["trimmed_leading"] == 0


def test_trim_disclosure_handles_both_dns_edges_and_irregular_plural(
    restore_display_utc,
) -> None:
    payload = build_dns(
        pd.DataFrame({
            "ts": [10.0],
            "src": ["192.0.2.10"],
            "query": ["example.test"],
        }),
        config=_config(),
        source_label="dns.log",
    )
    payload["meta"].update({
        "trimmed_leading": 1,
        "trimmed_trailing": 2,
        "trim_lead_epoch": 10.0,
        "trim_trail_epoch": 20.0,
        "altered_metric_cells": 3,
    })

    set_display_utc(True)
    note = _format_degrade_note(payload["meta"])

    assert note == (
        "trimmed 1 query before the retained window to focus the timeline "
        "(window begins 1970-01-01 00:00 UTC); "
        "trimmed 2 queries after the retained window to focus the timeline "
        "(window ends 1970-01-01 00:00 UTC); "
        "scaled 3 metric cells to the render ceiling"
    )
    assert "querys" not in note
    assert "started" not in note


def test_trim_disclosure_uses_the_local_display_timezone(
    pin_tz, restore_display_utc,
) -> None:
    pin_tz("Etc/GMT+6")
    set_display_utc(False)
    payload = build_conn(
        _conn_frame(ts=[10.0, 11.0]),
        config=_config(),
        source_label="conn.log",
    )
    payload["meta"].update({
        "trimmed_leading": 2,
        "trim_lead_epoch": 10.0,
    })

    note = _format_degrade_note(payload["meta"])

    assert note == (
        "trimmed 2 connections before the retained window to focus the timeline "
        "(window begins 1969-12-31 18:00 local)"
    )


def test_smooth_budget_caps_radius_without_folding_or_coarsening() -> None:
    """The dns regression keeps all 636 flows and all 1,440 day bins."""
    flow_count = 636
    frame = pd.DataFrame({
        "ts": [0.0 if index % 2 == 0 else 86_340.0 for index in range(flow_count)],
        "src": [f"192.0.2.{index % 30 + 1}" for index in range(flow_count)],
        "dst": [f"198.51.100.{index // 30 + 1}" for index in range(flow_count)],
        "svc": ["dns"] * flow_count,
        "metric": [1] * flow_count,
    })

    payload = build_payload(
        frame,
        kind="dns",
        source_label="dns.log",
        config=_config(target_bins=2000, top_hosts=30, top_services=16),
        meta={"kind": "dns"},
        default_window_note=None,
    )

    assert len(payload["flows"]) == flow_count
    assert payload["meta"]["bins"] == 1_440
    assert payload["meta"]["bin_seconds"] == 60
    assert payload["meta"]["natural_radius"] == 120
    assert payload["meta"]["max_radius"] == 108
    assert payload["meta"]["effective_top_hosts"] == 30
    assert payload["meta"]["effective_top_services"] == 16
    assert _format_degrade_note(payload["meta"]) == (
        "capped max smoothing to +/-108 bins to stay interactive"
    )
    assert (
        2 * flow_count * 1_440 * (2 * payload["meta"]["max_radius"] + 1)
        <= GRAPH_MAX_SMOOTH_OPS
    )


def test_flow_budget_uses_service_first_monotonic_max_fit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_core, "GRAPH_MAX_FLOWS", 4)
    monkeypatch.setattr(_core, "GRAPH_MAX_SMOOTH_OPS", 10**12)
    frame = pd.DataFrame({
        "ts": [0.0] * 10,
        "src": ["192.0.2.10"] * 10,
        "dst": ["198.51.100.10"] * 10,
        "svc": [f"svc-{index}" for index in range(10)],
        "metric": [1] * 10,
    })

    payload = build_payload(
        frame, kind="test", source_label="test.log",
        config=_config(top_hosts=1, top_services=10), meta={"kind": "test"},
        default_window_note=None,
    )

    assert payload["meta"]["effective_top_services"] == 3
    assert payload["meta"]["effective_top_hosts"] == 1
    assert len(payload["flows"]) == 4
    assert payload["svcNodes"][-1] == "(other)"


def test_smooth_budget_uses_the_player_half_up_slider_rounding(
) -> None:
    """A .5 slider tie matches JavaScript Math.round rather than banker rounding."""
    assert _core._slider_radius(318) == 27


def test_pair_budget_coarsens_bins_before_allocating_sparse_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _core.GRAPH_MAX_PAYLOAD_PAIRS == 1_500_000
    monkeypatch.setattr(_core, "GRAPH_MAX_PAYLOAD_PAIRS", 4)
    monkeypatch.setattr(_core, "GRAPH_MAX_SMOOTH_OPS", 10**12)
    frame = pd.DataFrame({
        "ts": [float(index) for index in range(10)],
        "src": ["192.0.2.10"] * 10,
        "dst": ["198.51.100.10"] * 10,
        "svc": ["dns"] * 10,
        "metric": [0] * 10,
    })

    payload = build_payload(
        frame, kind="test", source_label="test.log",
        config=_config(target_bins=20), meta={"kind": "test"},
        default_window_note=None,
    )

    assert payload["meta"]["requested_bin_seconds"] == 1
    assert payload["meta"]["bin_seconds"] == 5
    assert payload["meta"]["bins"] == 2
    assert sum(len(flow["b"]) + len(flow["c"]) for flow in payload["flows"]) == 8


def test_pair_descent_reaches_terminal_one_bin_beyond_nice_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_core, "GRAPH_MAX_PAYLOAD_PAIRS", 2)
    monkeypatch.setattr(_core, "GRAPH_MAX_SMOOTH_OPS", 10**12)
    frame = pd.DataFrame({
        "ts": [0.0, 604_801.0],
        "src": ["192.0.2.10"] * 2,
        "dst": ["198.51.100.10"] * 2,
        "svc": ["dns"] * 2,
        "metric": [1, 1],
    })

    payload = build_payload(
        frame, kind="test", source_label="test.log",
        config=_config(), meta={"kind": "test"},
        default_window_note=None,
    )

    assert payload["meta"]["bins"] == 1
    assert payload["meta"]["bin_seconds"] == 1_209_600
    assert payload["totC"] == [2]


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


def test_core_drops_out_of_range_timestamps_and_scales_unsafe_metrics() -> None:
    """Finite host-language magnitudes cannot create an invalid player payload."""
    with pytest.raises(GraphEmpty, match="no timestamped rows"):
        build_conn(
            _conn_frame(ts=[-1e308, 1e308]),
            config=_config(),
            source_label="conn.log",
        )

    saturated = build_conn(
        _conn_frame(bytes=[1e308, 1]),
        config=_config(),
        source_label="conn.log",
    )
    assert saturated["meta"]["altered_metric_cells"] == 1
    assert np.isfinite(np.float32(saturated["flows"][0]["b"][1]))

    # A player filter can select only positive flows, so signed net totals do
    # not prove Float32 safety. The absolute per-bin flow contribution is
    # scaled before serialization and survives player-style accumulation.
    mixed = build_payload(
        pd.DataFrame({
            "ts": [0.0, 0.0, 0.0],
            "src": ["192.0.2.10", "192.0.2.11", "192.0.2.12"],
            "dst": ["198.51.100.10"] * 3,
            "svc": ["dns"] * 3,
            "metric": [3e38, 3e38, -3e38],
        }),
        kind="test", source_label="test.log", config=_config(),
        meta={"kind": "test"}, default_window_note=None,
    )
    values = [flow["b"][1] for flow in mixed["flows"]]
    absolute_total = np.float32(0.0)
    for value in values:
        absolute_total = np.float32(absolute_total + np.float32(abs(value)))
    assert np.isfinite(absolute_total)
    assert mixed["meta"]["altered_metric_cells"] == 3
    assert "scaled 3 metric cells" in (_format_degrade_note(mixed["meta"]) or "")


def test_metric_scaling_stays_finite_after_many_float32_rounding_steps() -> None:
    """Builder proof reaches the player's rounded sequential accumulator."""
    count = 1_000
    frame = pd.DataFrame({
        "ts": [0.0] * count,
        "src": [f"192.0.2.{index % 250 + 1}" for index in range(count)],
        "dst": [f"198.51.100.{index // 250 + 1}" for index in range(count)],
        "svc": ["dns"] * count,
        "metric": [1e38 if index % 2 == 0 else -1e38 for index in range(count)],
    })

    payload = build_payload(
        frame, kind="test", source_label="test.log",
        config=_config(top_hosts=500), meta={"kind": "test"},
        default_window_note=None,
    )

    absolute_total = np.float32(0.0)
    for flow in payload["flows"]:
        absolute_total = np.float32(
            absolute_total + np.float32(abs(flow["b"][1]))
        )
    assert np.isfinite(absolute_total)
    assert payload["meta"]["altered_metric_cells"] == count


def test_metric_scaling_counts_only_cells_whose_metric_changed() -> None:
    """A count-only zero cell in a scaled bin is not a scaled metric cell."""
    payload = build_payload(
        pd.DataFrame({
            "ts": [0.0, 0.0, 0.0],
            "src": ["192.0.2.10", "192.0.2.11", "192.0.2.12"],
            "dst": ["198.51.100.10"] * 3,
            "svc": ["dns"] * 3,
            "metric": [3e38, 3e38, 0.0],
        }),
        kind="test",
        source_label="test.log",
        config=_config(),
        meta={"kind": "test"},
        default_window_note=None,
    )

    assert payload["meta"]["altered_metric_cells"] == 2
    assert sum(flow["c"][1] for flow in payload["flows"]) == 3


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


def test_evidence_window_extends_bins_without_leaking_meta_overrides() -> None:
    """An evidence-only tail reaches the player without inventing a data row."""
    frame = pd.DataFrame({
        "ts": [10.0],
        "src": ["192.0.2.10"],
        "dst": ["198.51.100.10"],
        "svc": ["dns"],
        "metric": [1],
    })

    payload = build_payload(
        frame,
        kind="test",
        source_label="test.log",
        config=_config(),
        meta={"hunt_hint": "not a runner hint"},
        default_window_note=None,
        window=(10.0, 20.0),
    )

    assert payload["meta"]["t0"] == 10.0
    assert payload["meta"]["t1"] == 20.0
    assert payload["meta"]["bins"] * payload["meta"]["bin_seconds"] >= 10.0
    assert payload["totB"][0] == 1
    assert payload["totC"][0] == 1
    assert all(value == 0 for value in payload["totB"][1:])
    assert all(value == 0 for value in payload["totC"][1:])
    assert payload["meta"]["hunt_hint"] is None


def test_evidence_window_invalid_bounds_fall_back_to_frame_extrema() -> None:
    """An invalid optional evidence window cannot disturb the existing frame."""
    frame = pd.DataFrame({
        "ts": [10.0, 11.0],
        "src": ["192.0.2.10", "192.0.2.10"],
        "dst": ["198.51.100.10", "198.51.100.10"],
        "svc": ["dns", "dns"],
        "metric": [1, 1],
    })
    baseline = build_payload(
        frame, kind="test", source_label="test.log", config=_config(),
        meta={}, default_window_note=None,
    )
    invalid = build_payload(
        frame, kind="test", source_label="test.log", config=_config(),
        meta={}, default_window_note=None, window=(math.nan, 20.0),
    )

    baseline["meta"].pop("generated_utc")
    invalid["meta"].pop("generated_utc")
    assert invalid == baseline


def test_attach_hunt_hint_is_none_safe_and_owns_the_typed_slot() -> None:
    """Only the post-build setter writes the control-cleaned hint field."""
    payload = {"meta": {"hunt_hint": None}}

    attach_hunt_hint(payload, None)
    assert payload["meta"]["hunt_hint"] is None

    attach_hunt_hint(payload, "sigwood hunt /tmp/a\x1b")
    assert payload["meta"]["hunt_hint"] == "sigwood hunt /tmp/a"

    with pytest.raises(AssertionError):
        attach_hunt_hint({"meta": {}}, "sigwood hunt /tmp/a")


def test_weighted_count_mode_preserves_fractional_query_mass() -> None:
    """Weight mode keeps pihole-style c shares instead of counting split rows."""
    frame = pd.DataFrame({
        "ts": [0.0, 0.0],
        "src": ["192.0.2.10", "192.0.2.10"],
        "dst": ["ads.example.com", "ads.example.com"],
        "svc": ["cached", "forwarded"],
        "metric": [0.6, 0.4],
    })

    payload = build_payload(
        frame,
        kind="pihole",
        source_label="pihole.log",
        config=_config(target_bins=1),
        meta={},
        default_window_note=None,
        count_by="weight",
        row_count=1,
    )

    assert payload["meta"]["rows"] == 1
    assert payload["meta"]["weighted"] is True
    assert payload["totB"] == pytest.approx([1.0])
    assert payload["totC"] == pytest.approx([1.0])
    assert all(isinstance(value, float) for value in payload["totC"])
    assert sorted(flow["c"][1] for flow in payload["flows"]) == pytest.approx([0.4, 0.6])


def test_count_mode_owns_weighted_metadata_over_builder_extras() -> None:
    """Builder metadata cannot contradict the payload count wire."""
    frame = pd.DataFrame({
        "ts": [0.0],
        "src": ["192.0.2.10"],
        "dst": ["ads.example.com"],
        "svc": ["cached"],
        "metric": [0.5],
    })

    weighted = build_payload(
        frame,
        kind="pihole",
        source_label="pihole.log",
        config=_config(target_bins=1),
        meta={"weighted": False},
        default_window_note=None,
        count_by="weight",
    )
    counted = build_payload(
        frame,
        kind="dns",
        source_label="dns.log",
        config=_config(target_bins=1),
        meta={"weighted": True},
        default_window_note=None,
    )

    assert weighted["meta"]["weighted"] is True
    assert counted["meta"]["weighted"] is False


@pytest.mark.parametrize("weight", [-1.0, math.nan, math.inf, None])
def test_weighted_count_mode_rejects_invalid_weight_values(weight: object) -> None:
    """Weight mode refuses a builder bug rather than coercing it to zero."""
    frame = pd.DataFrame({
        "ts": [0.0],
        "src": ["192.0.2.10"],
        "dst": ["ads.example.com"],
        "svc": ["cached"],
        "metric": [weight],
    })

    with pytest.raises(ValueError, match="metric values are too large"):
        build_payload(
            frame,
            kind="pihole",
            source_label="pihole.log",
            config=_config(),
            meta={},
            default_window_note=None,
            count_by="weight",
        )


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
