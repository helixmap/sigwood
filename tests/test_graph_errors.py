"""Control-signal contracts for the graph verb foundation."""

from __future__ import annotations

from sigwood.common.errors import GraphEmpty, GraphSourceUnreadable


def test_graph_empty_carries_multi_input_context() -> None:
    exc = GraphEmpty("conn", "first.log, second.log", "no timestamped rows")

    assert not issubclass(GraphEmpty, ValueError)
    assert exc.kind == "conn"
    assert exc.source_label == "first.log, second.log"
    assert exc.reason == "no timestamped rows"
    assert str(exc) == (
        "recognized first.log, second.log as conn but no renderable records - "
        "no timestamped rows"
    )


def test_graph_source_unreadable_carries_typed_bucket_context() -> None:
    exc = GraphSourceUnreadable(
        "dns",
        "dns.log",
        "permission denied reading dns.log",
    )

    assert not issubclass(GraphSourceUnreadable, ValueError)
    assert exc.kind == "dns"
    assert exc.source_label == "dns.log"
    assert exc.message == "permission denied reading dns.log"
    assert str(exc) == "permission denied reading dns.log"
