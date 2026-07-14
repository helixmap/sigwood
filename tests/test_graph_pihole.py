"""Pi-hole graph-builder contracts."""

from __future__ import annotations

import math

import pandas as pd
import pytest

from sigwood.common.errors import GraphEmpty
from sigwood.graph import _core
from sigwood.graph._core import validate_config
from sigwood.graph.pihole import _DISPOSITIONS, build
from sigwood.outputs.graph import render_graph_html


def _config(**overrides: object) -> dict[str, object]:
    return validate_config({"target_bins": 1, **overrides})


def _rows() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"ts": 10.0, "src": "192.0.2.10", "query": "ads.example.com", "event_type": "query"},
            {"ts": 11.0, "src": "192.0.2.11", "query": "ads.example.com", "event_type": "query"},
            {"ts": 12.0, "src": "192.0.2.12", "query": "orphan.example.net", "event_type": "query"},
            {"ts": 20.1, "src": None, "query": "ads.example.com", "event_type": "cached"},
            {"ts": 20.8, "src": None, "query": "ads.example.com", "event_type": "cached"},
            {"ts": 21.0, "src": None, "query": "ads.example.com", "event_type": "cached"},
            {"ts": 22.0, "src": None, "query": "ads.example.com", "event_type": "cached"},
            {"ts": 23.0, "src": None, "query": "ads.example.com", "event_type": "forwarded"},
            {"ts": 24.0, "src": None, "query": "ads.example.com", "event_type": "forwarded"},
            {"ts": 25.0, "src": None, "query": "ads.example.com", "event_type": "reply"},
        ]
    )


def _service_mass(payload: dict[str, object]) -> dict[str, float]:
    names = payload["svcNodes"]
    totals: dict[str, float] = {}
    for flow in payload["flows"]:
        service = names[flow["v"]]
        totals[service] = totals.get(service, 0.0) + sum(flow["c"][1::2])
    return totals


def test_pihole_builder_deduplicates_raw_dispositions_and_weights_queries() -> None:
    """Raw-query dedup precedes roll and weighted c mass stays query-honest."""
    payload = build(_rows(), config=_config(), source_label="pihole.log")

    masses = _service_mass(payload)
    assert payload["meta"]["rows"] == 3
    assert payload["meta"]["weighted"] is True
    assert payload["meta"]["metric_note"] == "weighted by disposition share"
    assert masses == pytest.approx({"cached": 1.2, "forwarded": 0.8, "(unattributed)": 1.0})
    assert sum(payload["totC"]) == pytest.approx(3.0)
    assert all(isinstance(value, float) for value in payload["totC"])


def test_pihole_disposition_taxonomy_stays_narrow() -> None:
    """Only the four approved parser outcomes enter the disposition spine."""
    assert _DISPOSITIONS == {
        "gravity_blocked": "blocked",
        "regex_blocked": "blocked",
        "cached": "cached",
        "forwarded": "forwarded",
        "config": "local",
    }


def test_pihole_builder_keeps_three_way_fractional_shares_nonzero() -> None:
    """A three-way domain share cannot be rounded out before the player sees it."""
    rows = pd.DataFrame(
        [
            {"ts": 10.0, "src": "192.0.2.10", "query": "mix.example.com", "event_type": "query"},
            {"ts": 20.0, "src": None, "query": "mix.example.com", "event_type": "cached"},
            {"ts": 21.0, "src": None, "query": "mix.example.com", "event_type": "forwarded"},
            {"ts": 22.0, "src": None, "query": "mix.example.com", "event_type": "config"},
        ]
    )

    payload = build(rows, config=_config(), source_label="pihole.log")

    assert sorted(_service_mass(payload).values()) == pytest.approx([1 / 3] * 3)
    assert sum(payload["totC"]) == pytest.approx(1.0)
    assert all(value != 0 for flow in payload["flows"] for value in flow["c"][1::2])


def test_pihole_evidence_window_includes_a_late_disposition_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The replay frame retains attribution evidence after the final query."""
    rows = pd.DataFrame(
        [
            {"ts": 10.0, "src": "192.0.2.10", "query": "relay.example.test", "event_type": "query"},
            {"ts": 20.0, "src": None, "query": "relay.example.test", "event_type": "forwarded"},
        ]
    )

    monkeypatch.setattr(
        _core,
        "_trim_sparse_edges",
        lambda *args, **kwargs: pytest.fail(
            "Pi-hole evidence windows must bypass sparse-edge trimming"
        ),
    )
    payload = build(
        rows,
        config=validate_config({}),
        source_label="pihole.log",
        trim_sparse_edges=True,
    )

    assert payload["meta"]["t0"] == 10.0
    assert payload["meta"]["t1"] == 20.0
    assert payload["meta"]["bins"] * payload["meta"]["bin_seconds"] >= 10.0
    assert _service_mass(payload) == pytest.approx({"forwarded": 1.0})
    assert all(value == 0 for value in payload["totB"][1:])
    assert all(value == 0 for value in payload["totC"][1:])


def test_pihole_builder_excludes_blank_and_bad_time_queries_before_counting() -> None:
    """Invalid query identities never materialize as an unknown destination."""
    rows = pd.DataFrame(
        [
            {"ts": math.nan, "src": "192.0.2.10", "query": "drop.example.com", "event_type": "query"},
            {"ts": 10.0, "src": "192.0.2.11", "query": "   ", "event_type": "query"},
            {"ts": 11.0, "src": "192.0.2.12", "query": "keep.example.com", "event_type": "query"},
            {"ts": math.inf, "src": None, "query": "keep.example.com", "event_type": "cached"},
        ]
    )

    payload = build(rows, config=_config(), source_label="pihole.log")

    assert payload["meta"]["rows"] == 1
    assert "(unknown)" not in [node["id"] for node in payload["dstNodes"]]
    assert _service_mass(payload) == pytest.approx({"(unattributed)": 1.0})


def test_pihole_builder_raises_clean_empty_without_an_accepted_query() -> None:
    """A pihole frame with no valid query row remains a GraphEmpty result."""
    rows = pd.DataFrame(
        [
            {"ts": math.nan, "src": "192.0.2.10", "query": "bad.example.com", "event_type": "query"},
            {"ts": 10.0, "src": None, "query": "", "event_type": "cached"},
        ]
    )

    with pytest.raises(GraphEmpty, match="no query rows"):
        build(rows, config=_config(), source_label="pihole.log")


def test_pihole_labels_stay_inside_the_existing_safe_payload_choke_point() -> None:
    """A hostile query name cannot close the graph data script."""
    rows = pd.DataFrame(
        [
            {
                "ts": 10.0,
                "src": "192.0.2.10",
                "query": "evil</script><script>alert(1)</script>.example.test",
                "event_type": "query",
            },
        ]
    )

    artifact = render_graph_html(build(rows, config=_config(), source_label="pihole.log"))
    blob = artifact.split("const DATA = ", 1)[1].split(";</script>", 1)[0]

    assert "<" not in blob
    assert r"\u003c/script>" in blob
