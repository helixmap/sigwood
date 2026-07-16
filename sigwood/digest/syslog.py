"""syslog summariser - orient-before-the-hunt for fidelity-aware syslog.

The thinnest digest card by design - three slots, no manufactured depth.
A three-row syslog card beside a six-row dns card honestly reads as "syslog
is simpler," which is true; flat-grammar selection keeps it scannable.

Slots (fixed order):
  - host-volume    - cliff over per-host line counts (feed-independent)
  - program-volume - cliff over per-program line counts (feed-independent)
  - error-rate     - rate of lines that are "errors"; KIND forks on feed

Fidelity fork (DNS precedent):

  - feed ``"syslog"`` (flat rsyslog): the normalized frame carries no
    PRI-derived severity under either RFC 3164 or ISO-8601, so "error" is a
    keyword-token heuristic over the message body. Kind definition like
    dns's "rcode == 3", not a badness threshold - gated only by RATE_FLOOR.
  - feed ``"zeek"`` (Zeek syslog.log): Zeek emits an explicit ``severity``
    enum on every line, so "error" is the real RFC 5424 error set
    ``{EMERG, ALERT, CRIT, ERR}``. No keyword guessing.

The lede formatter for ``error-rate`` forks its wording on ``feed`` - the
Zeek arm speaks in severity terms, the flat arm in token terms. The card
itself carries no footer surface under the flat grammar; the feed-difference
disclosure is implicit in the insight wording.

Cliff machinery imported from conn so the cards cannot drift on gate /
floor / display-cap behaviour. The rate statistic and its RATE_FLOOR
constant live in ``sigwood.digest._stats`` - factored once three cards
needed an identical copy (this one, dns, and cloudtrail).
"""

from __future__ import annotations

import re

import pandas as pd

from sigwood.common.finding import DigestSlot
from sigwood.digest._stats import RATE_FLOOR, _rate
from sigwood.digest.conn import (
    CLIFF_DISPLAY_CAP,  # noqa: F401 - re-exported for downstream symmetry
    CLIFF_GATE,         # noqa: F401 - re-exported for downstream symmetry
    POPULATION_FLOOR,
    _cliff,
    _format_ratio_cell,
    _format_ratio_lede,
)


# ── Calibration constants ───────────────────────────────────────────────────

# Kind-definition heuristic. The normalized syslog frame carries no severity
# field - flat rsyslog exposes no PRI-derived severity, RFC 3164 or ISO-8601.
# This is plain text matching against an error-indicating token list, sorted
# longest-first so multi-word phrases survive alternation as the list grows.
_ERROR_TOKENS = (
    "out of memory",
    "unreachable",
    "segfault",
    "critical",
    "failure",
    "refused",
    "timeout",
    "denied",
    "failed",
    "error",
    "fatal",
    "panic",
    "oom",
)

# Start-boundary at the alternation, free suffix at the end. So "errors" matches
# "error" (start-bounded), "oom-killer" matches "oom" (hyphen is non-word),
# "out of memory" matches as a literal phrase, but "terror" does NOT match
# "error" (no word boundary before "error" when preceded by a word char).
_ERROR_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(t) for t in _ERROR_TOKENS) + r")",
    re.IGNORECASE,
)

# Zeek-feed kind: real RFC 5424 error severities. Uppercase enum strings on
# the wire ("EMERG", "ALERT", "CRIT", "ERR") - matched case-insensitively to
# absorb mixed-case Zeek emissions without column-sniffing the case shape.
_SEVERITY_ERROR_SET = frozenset({"EMERG", "ALERT", "CRIT", "ERR"})

# ── Slot computers ──────────────────────────────────────────────────────────

def _slot_host_volume(frame: pd.DataFrame) -> DigestSlot:
    """host-volume - cliff over per-host line counts."""
    label = "host-volume"
    if frame.empty or "host" not in frame.columns:
        return DigestSlot(label=label, statistic="cliff")
    counts = frame["host"].value_counts(dropna=True).sort_values(ascending=False)
    result = _cliff(counts)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    entity, magnitude, ratio = result
    total = len(frame)
    share_pct = (magnitude / total * 100.0) if total > 0 else 0.0
    entity_str = str(entity)
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[entity_str, f"{share_pct:.0f}%", _format_ratio_cell(ratio)],
        entity=entity_str,
        magnitude=share_pct,
        ratio=ratio,
    )


def _slot_program_volume(frame: pd.DataFrame) -> DigestSlot:
    """program-volume - cliff over per-program line counts."""
    label = "program-volume"
    if frame.empty or "program" not in frame.columns:
        return DigestSlot(label=label, statistic="cliff")
    counts = frame["program"].value_counts(dropna=True).sort_values(ascending=False)
    result = _cliff(counts)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    entity, magnitude, ratio = result
    entity_str = str(entity)
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[entity_str, f"{int(magnitude)}", _format_ratio_cell(ratio)],
        entity=entity_str,
        magnitude=magnitude,
        ratio=ratio,
    )


def _slot_error_rate(frame: pd.DataFrame, feed: str) -> DigestSlot:
    """error-rate - fraction of lines that are "errors". Kind forks on feed.

    feed ``"zeek"``  : kind = ``severity`` ∈ {EMERG, ALERT, CRIT, ERR}. The
                       severity column may be absent on a malformed Zeek frame
                       - slot dashes in that case. Present-but-zero error-set
                       values flows through ``_rate`` and dashes via the
                       shared RATE_FLOOR (matching the flat-feed convention -
                       neither feed paints "0%").
    feed ``"syslog"``: kind = message-text keyword match (``_ERROR_RE``).
                       Matching is against the canonical ``message`` column
                       only (header-stripped body), never ``raw`` - the
                       unstripped line would let timestamps or hostnames
                       accidentally trip tokens.

    Kind definition, not badness threshold: the fraction is reported as a
    plain fact, gated only by the shared RATE_FLOOR.
    """
    label = "error-rate"
    if frame.empty or "host" not in frame.columns:
        return DigestSlot(label=label, statistic="rate")

    if feed == "zeek":
        if "severity" not in frame.columns:
            return DigestSlot(label=label, statistic="rate")
        severity = frame["severity"].astype(str).str.upper()
        kind_mask = severity.isin(_SEVERITY_ERROR_SET)
    else:
        if "message" not in frame.columns:
            return DigestSlot(label=label, statistic="rate")
        messages = frame["message"].astype(str)
        kind_mask = messages.str.contains(_ERROR_RE, na=False)

    result = _rate(kind_mask, frame["host"])
    if result is None:
        return DigestSlot(label=label, statistic="rate")
    fraction, top = result
    pct = fraction * 100.0
    return DigestSlot(
        label=label,
        statistic="rate",
        cells=[f"{pct:.0f}%", top],
        entity=top,
        magnitude=pct,
    )


# ── Lede formatters ─────────────────────────────────────────────────────────

def _lede_host_volume(slot: DigestSlot, feed: str) -> str:
    return (
        f"{slot.entity} emitted {slot.magnitude:.0f}% of log lines, "
        f"{_format_ratio_lede(slot.ratio)} the next host."
    )


def _lede_program_volume(slot: DigestSlot, feed: str) -> str:
    return (
        f"{slot.entity} emitted {int(slot.magnitude)} lines, "
        f"{_format_ratio_lede(slot.ratio)} the next program."
    )


def _lede_error_rate(slot: DigestSlot, feed: str) -> str:
    """error-rate lede - wording forks on feed.

    The Zeek variant MUST NOT say "token" or imply keyword matching - that
    would misdescribe the real-severity Zeek path. The flat-syslog variant
    keeps the existing keyword wording.
    """
    if feed == "zeek":
        return (
            f"{slot.magnitude:.0f}% of lines are error-severity "
            f"(ERR or higher), led by {slot.entity}."
        )
    return (
        f"{slot.magnitude:.0f}% of lines carry an error token, "
        f"led by {slot.entity}."
    )


def _insight_formatters(feed: str) -> dict[str, "Callable[[DigestSlot], str]"]:
    """Bind ``feed`` into the feed-aware formatters so the shared selection
    helper sees the standard ``(slot) -> str`` shape.

    A small dedicated helper rather than a sentinel - the formatters take
    feed explicitly, and partial-binding here is the obvious mechanism.
    """
    return {
        "host-volume":    lambda slot: _lede_host_volume(slot, feed),
        "program-volume": lambda slot: _lede_program_volume(slot, feed),
        "error-rate":     lambda slot: _lede_error_rate(slot, feed),
    }


# ── Zone 1 extras ───────────────────────────────────────────────────────────

def _zone1_extras(frame: pd.DataFrame) -> list[tuple[str, str]]:
    """Two lines, brief-pinned: distinct hosts + distinct programs."""
    if frame.empty:
        return [("hosts", "0"), ("programs", "0")]
    distinct_hosts = (
        int(frame["host"].nunique(dropna=True)) if "host" in frame.columns else 0
    )
    distinct_programs = (
        int(frame["program"].nunique(dropna=True)) if "program" in frame.columns else 0
    )
    return [
        ("hosts", str(distinct_hosts)),
        ("programs", str(distinct_programs)),
    ]


# ── Public entry point ─────────────────────────────────────────────────────

def summarize(frame: pd.DataFrame, feed: str) -> dict:
    """Return the schema-specific body of a syslog DigestCard.

    ``feed`` is ``"zeek"`` or ``"syslog"`` - picks which kind drives the
    error-rate slot and which wording the lede uses. Host- and program-volume
    cliffs are feed-independent.
    """
    from sigwood.digest._stats import select_insights_and_fields

    slots = [
        _slot_host_volume(frame),
        _slot_program_volume(frame),
        _slot_error_rate(frame, feed),
    ]
    insights, fields = select_insights_and_fields(
        slots, _insight_formatters(feed),
    )
    return {
        "zone1_extras": _zone1_extras(frame),
        "insights": insights,
        "fields": fields,
    }
