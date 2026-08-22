"""digest verb - orient-before-the-hunt.

A digest characterises the dominant shape of a log pile and states facts
about it. It is a peer verb to detect, not a detector. Digest never produces
a Finding and never reaches a verdict.

One summariser module per schema. Each summariser is a function
``summarize(frame) -> dict`` returning the schema-specific body of a
DigestCard. The dispatcher below imports the right module by schema name; to
add a new schema, drop a new module beside conn.py and nothing else changes.

Architectural rail: digest consumes the loaded frame BEFORE the allowlist
filtering seam. Allowlisted infrastructure (resolvers, pollers) is part of
what's in the pile and stays on the sonar. The digest call graph must not
touch build_matcher or AllowlistMatcher.filter_df.
"""

from __future__ import annotations

from importlib import import_module
from typing import Callable

import pandas as pd


def get_summarizer(schema: str) -> Callable[..., dict]:
    """Return the summarize() function for a given digest schema.

    The dispatcher returns the bare callable; per-schema signatures may
    differ. Today: ``conn``, ``weird``, and ``cloudtrail`` take ``(frame)``;
    ``dns`` takes ``(frame, feed)`` where feed is ``"zeek"`` or
    ``"pihole"``; ``syslog`` takes ``(frame, feed)`` where feed is
    ``"zeek"`` or ``"syslog"`` (flat rsyslog). Callers (currently only
    ``run_digest``) know how to invoke the right signature per schema.

    Raises ValueError with an actionable message when no summariser
    exists for the requested schema.
    """
    try:
        module = import_module(f"sigwood.digest.{schema}")
    except ModuleNotFoundError as exc:
        raise ValueError(f"digest: no summarizer for schema {schema!r}") from exc
    return module.summarize
