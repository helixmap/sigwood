"""Narrow extraction of the full Linux audit event identity.

This helper is temporarily separate from ``parsers.auth`` because the latter is
hash-pinned by a frozen measurement instrument.  Keep the behavioral parity pin
until a successor parser can own both the serial and full identity.
"""

from __future__ import annotations

import re


_AUDIT_EVENT_ID_RE = re.compile(
    r"(?:^|\s)msg=audit\("
    r"(?P<event_id>(?P<epoch>[^:)]*):(?P<serial>[^)]+))\):?"
)


def extract_audit_event_id(text: str) -> str | None:
    """Return ``epoch:serial`` only for a complete ``msg=audit(...)`` token."""
    event = _AUDIT_EVENT_ID_RE.search(text)
    if event is None:
        return None
    event_id = event.group("event_id")
    return event_id or None
