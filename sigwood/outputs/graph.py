"""Self-contained graph artifact rendering.

The graph player embeds a JSON payload in a script element.  This is a distinct
sink from the script-free HTML report, so this module owns the complete
serialization boundary: callers provide structured data and receive one HTML
document with no opportunity to inject markup or executable script.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any


_MARKER = "__SIGWOOD_GRAPH_DATA__"


def _embed_payload(payload: dict[str, Any], template: str) -> str:
    """Embed one strict JSON payload in the graph-player template.

    A JSON string in a script context needs stronger handling than ordinary
    HTML escaping: every literal less-than character is represented as the
    six-character \\u003c escape so neither a closing script tag nor the HTML
    double-escape state can be supplied by log data.
    """
    marker_count = template.count(_MARKER)
    if marker_count != 1:
        raise ValueError(
            f"graph template must contain exactly one payload marker (found {marker_count})"
        )
    blob = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).replace("<", "\\u003c")
    return template.replace(_MARKER, blob, 1)


def render_graph_html(payload: dict[str, Any]) -> str:
    """Render a graph payload into the packaged self-contained player."""
    template = (
        resources.files("sigwood.outputs")
        .joinpath("graph_player.html")
        .read_text(encoding="utf-8")
    )
    return _embed_payload(payload, template)
