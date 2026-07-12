"""Graph payload builders for the replay-oriented graph verb."""

from __future__ import annotations

from importlib import import_module
from typing import Any, Callable

from sigwood.common.sources import GRAPH_KINDS


def supported_kinds() -> tuple[str, ...]:
    """Return graph kinds in their public deterministic order."""
    return tuple(spec.kind for spec in GRAPH_KINDS)


def get_builder(kind: str) -> Callable[..., dict[str, Any]]:
    """Return the graph builder registered for one supported kind."""
    if kind not in supported_kinds():
        choices = ", ".join(supported_kinds())
        raise ValueError(f"unsupported graph kind {kind!r} (supported: {choices})")
    module = import_module(f"sigwood.graph.{kind}")
    return module.build
