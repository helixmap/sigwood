"""dnsmasq/Pi-hole log parsing - extract structured event dicts for loader assembly.

Provides pure parsing functions with no file I/O.  File discovery, DataFrame
construction, and hostname assignment are handled by loader.py via load_pihole().

Known limitation: dnsmasq logs carry no timezone information.  Timestamps are
interpreted as the host's LOCAL wall-clock (the timezone dnsmasq writes in) and
converted to true UTC, matching the behaviour of parsers/syslog.py.  Wall-clock
logs written on a box in a different timezone from the one running sigwood
(shipped or exported logs) remain offset from true UTC by the timezone
difference.

Canonical-plus-event schema
────────────────────────────
The parser emits one dict per parsed event line.  Fields divide into two groups:

Canonical DNS fields (shared vocabulary with the Zeek path):
  ts     - UTC-aware datetime or None
  src    - querying client IP (str | None; populated ONLY on query events)
  query  - queried domain (str | None; the "domain" of the event where applicable)

dnsmasq event fields (parser-specific):
  event_type - query | forwarded | reply | cached | gravity_blocked |
               config | validation | dnssec_query | special | dhcp |
               pihole_hostname | regex_blocked | unknown
  qtype      - query type (A, AAAA, HTTPS, …) (str | None; query and dnssec_query events)
  host       - source host, set by the loader from filename (parser leaves "")

The parser retains only fields that shipped consumers use.  Future detectors
promote their source fields at their own planning seam rather than retaining
every line payload in every loaded row.

Rule for detector authors: features may depend on the canonical fields (ts, src,
query) freely.  Any feature derived from the dnsmasq event fields must be guarded
(presence-checked) so the same detector code can run against a Zeek frame that
lacks them.
"""

from __future__ import annotations

import re
from datetime import datetime

from sigwood.parsers.syslog import parse_timestamp

# ── Compiled patterns ─────────────────────────────────────────────────────────

# Outer grammar: Mon DD HH:MM:SS [hostname] dnsmasq[PID]: <message>
# Single-digit days appear with a leading space (dnsmasq format); \s+ handles both.
_OUTER_RE = re.compile(
    r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    r'\s+(?:\S+\s+)?dnsmasq\[\d+\]:\s+'
    r'(?P<message>.+)$'
)

# Inner message grammars - evaluated in order, first match wins.
_QUERY_RE   = re.compile(
    r'^query\[(?P<qtype>[^\]]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<src>\S+)'
)
_FWD_RE     = re.compile(
    r'^forwarded\s+(?P<domain>\S+)\s+to\s+(?P<dst>\S+)'
)
_REPLY_RE   = re.compile(
    r'^reply\s+(?P<domain>\S+)\s+is\s+(?P<answer>.+)$'
)
_CACHED_RE  = re.compile(
    r'^(?:cached(?:-stale)?)\s+(?P<domain>\S+)\s+is\s+(?P<answer>.+)$'
)
_GRAVITY_RE = re.compile(
    r'^gravity blocked (?:\([^\)]+\)\s+)?(?P<domain>\S+) is (?P<answer>.+)$'
)
_CONFIG_RE  = re.compile(
    r'^(?P<source>/\S+|config)\s+(?P<domain>\S+)\s+is\s+(?P<answer>.+)$'
)
_VALID_RE   = re.compile(
    r'^validation result is (?P<status>\S+)'
)
# dnssec-query: resolver-internal DNSSEC validation traffic. Must precede _FWD_RE
# as future-proofing - today _FWD_RE starts with "forwarded" so there is no live
# conflict, but both patterns contain " to " and this ordering makes the intent explicit.
_DNSSEC_QUERY_RE = re.compile(
    r'^dnssec-query\[(?P<qtype>[^\]]+)\]\s+(?P<domain>\S+)\s+to\s+(?P<dst>\S+)'
)
# special domain: Apple Private Relay / resolver override disposition. Must precede
# _CONFIG_RE as future-proofing - today _CONFIG_RE starts with "/" or "config" so
# there is no live conflict, but both match "<token> <domain> is <answer>".
_SPECIAL_RE = re.compile(
    r'^special domain\s+(?P<domain>\S+)\s+is\s+(?P<answer>.+)$'
)
# Pi-hole hostname self-resolution. Must precede _CONFIG_RE for the same reason as
# _SPECIAL_RE - the "Pi-hole hostname" literal prefix is unambiguous today but the
# ordering makes the intent explicit.
_PIHOLE_HOSTNAME_RE = re.compile(
    r'^Pi-hole hostname\s+(?P<domain>\S+)\s+is\s+(?P<answer>.+)$'
)
# Regex/blacklist block disposition. Covers the spelling variants FTL emits across
# versions: "regex denied", "regex blacklisted", "exactly denied", "exactly blacklisted",
# and bare "blacklisted". Must precede _CONFIG_RE - the "<token(s)> <domain> is <answer>"
# shape overlaps, and the literal disposition prefix is unambiguous.
_REGEX_BLOCKED_RE = re.compile(
    r'^(?P<disposition>regex (?:denied|blacklisted)|exactly (?:denied|blacklisted)|blacklisted)'
    r'\s+(?P<domain>\S+)\s+is\s+(?P<answer>.+)$'
)
# DHCP lease lines ride the same log file. Both field orders occur in the wild:
# "DHCP <ip> is <hostname>" AND "DHCP <hostname> is <ip>".
_DHCP_RE    = re.compile(
    r'^DHCP\s+(?P<a>\S+)\s+is\s+(?P<b>\S+)'
)


# ── Parsing functions ─────────────────────────────────────────────────────────

def parse_line(raw: str) -> dict | None:
    """Parse a raw dnsmasq log line into a normalized event dict.

    Returns None for blank lines, comment lines (starting with #), and lines
    that do not match the dnsmasq outer grammar.

    Returns a dict with the canonical-plus-event schema described in the module
    docstring.  All keys are always present.  The 'host' field is left as "" -
    the loader fills it from the filename stem before building the DataFrame.
    The 'event_type' is "unknown" when the outer grammar matches but no inner
    grammar does; 'query' is None in that case. Unknown rows remain available
    as count-bearing parser evidence; extending the grammar recovers their
    source-line content from the log rather than from the loaded frame.
    """
    if not raw or raw.lstrip().startswith("#"):
        return None

    m = _OUTER_RE.match(raw.strip())
    if not m:
        return None

    message = m.group("message")
    ts: datetime | None = parse_timestamp(raw)

    result: dict = {
        "ts":         ts,
        "src":        None,
        "query":      None,
        "event_type": "unknown",
        "qtype":      None,
        "host":       "",
    }

    m_q = _QUERY_RE.match(message)
    if m_q:
        result.update({
            "event_type": "query",
            "qtype":      m_q.group("qtype"),
            "query":      m_q.group("domain"),
            "src":        m_q.group("src"),
        })
        return result

    # dhcp rows are non-DNS DHCP lease events that ride the dnsmasq log file.
    # They are excluded from all DNS analysis. Parsed here only to keep the unknown
    # bucket clean and to let the detector trivially filter with event_type == "dhcp".
    m_dhcp = _DHCP_RE.match(message)
    if m_dhcp:
        result.update({
            "event_type": "dhcp",
        })
        return result

    # dnssec-query events are resolver-internal DNSSEC validation traffic keyed to
    # zone-cut labels and root-style validation targets (e.g. example.test, or the
    # root zone) that frequently NEVER appear as a client query. They must NOT be
    # counted as "forwarded" events and must NOT be merged into per-domain query
    # aggregation by default - doing so would inflate forward_ratio for domains with
    # zero client queries and reproduce the divide-by-zero/infinite-ratio problem
    # observed during exploration. Capture now; defer feature use to a deliberate
    # later decision.
    m_dq = _DNSSEC_QUERY_RE.match(message)
    if m_dq:
        result.update({
            "event_type": "dnssec_query",
            "qtype":      m_dq.group("qtype"),
            "query":      m_dq.group("domain"),
        })
        return result

    m_f = _FWD_RE.match(message)
    if m_f:
        result.update({
            "event_type": "forwarded",
            "query":      m_f.group("domain"),
        })
        return result

    m_r = _REPLY_RE.match(message)
    if m_r:
        result.update({
            "event_type": "reply",
            "query":      m_r.group("domain"),
        })
        return result

    m_c = _CACHED_RE.match(message)
    if m_c:
        result.update({
            "event_type": "cached",
            "query":      m_c.group("domain"),
        })
        return result

    m_g = _GRAVITY_RE.match(message)
    if m_g:
        result.update({
            "event_type": "gravity_blocked",
            "query":      m_g.group("domain"),
        })
        return result

    m_sp = _SPECIAL_RE.match(message)
    if m_sp:
        result.update({
            "event_type": "special",
            "query":      m_sp.group("domain"),
        })
        return result

    # pihole_hostname rows are Pi-hole's own host self-resolution chatter (FTL
    # answering for its own hostname). They have no DNS hunting value and are
    # excluded from all DNS aggregation. Parsed here only to keep the unknown
    # bucket clean; the detector filters them out with event_type == "pihole_hostname".
    m_ph = _PIHOLE_HOSTNAME_RE.match(message)
    if m_ph:
        result.update({
            "event_type": "pihole_hostname",
            "query":      m_ph.group("domain"),
        })
        return result

    # regex_blocked and gravity_blocked are TWO mechanisms of the SAME outcome
    # (Pi-hole refused to resolve). The parser keeps them DISTINCT because the
    # gravity-vs-regex distinction is a real Pi-hole config detail worth preserving
    # at the source. The DETECTOR is responsible for collapsing both into a single
    # "blocked" notion when computing block_ratio / was_blocked - do not collapse
    # them here. (Separation of powers: parser stays faithful to the source; detector
    # owns the abstraction.)
    m_rb = _REGEX_BLOCKED_RE.match(message)
    if m_rb:
        result.update({
            "event_type": "regex_blocked",
            "query":      m_rb.group("domain"),
        })
        return result

    m_cf = _CONFIG_RE.match(message)
    if m_cf:
        result.update({
            "event_type": "config",
            "query":      m_cf.group("domain"),
        })
        return result

    m_v = _VALID_RE.match(message)
    if m_v:
        result.update({
            "event_type": "validation",
        })
        return result

    # No inner grammar matched - return as unknown; query stays None.
    return result


SNIFF_PEEK_LINES: int = 32

# Event types that prove the file is a dnsmasq/Pi-hole DNS log. dhcp and
# unknown are intentionally absent - they may precede the first DNS event
# but never claim "dns" on their own.
_DNS_BEARING_EVENT_TYPES: frozenset[str] = frozenset({
    "query", "forwarded", "reply", "cached",
    "gravity_blocked", "regex_blocked",
    "config", "validation",
    "dnssec_query", "special", "pihole_hostname",
})


def sniff(sample: list[str]) -> str | None:
    """Recognize a dnsmasq/Pi-hole DNS log and return "dns".

    Calls ``parse_line`` on each sample line and inspects ``event_type``.
    Returns "dns" on the first line whose event_type is a DNS-bearing kind
    (query/forwarded/reply/cached/gravity_blocked/regex_blocked/config/
    validation/dnssec_query/special/pihole_hostname). Tolerates leading
    runs of DHCP-lease or unknown dnsmasq chatter - they do not short-
    circuit. Returns None when the budget is exhausted without a
    DNS-bearing event, or when no line matches the dnsmasq outer grammar.

    Pure: takes already-decoded lines, performs no I/O.
    """
    for raw_line in sample:
        record = parse_line(raw_line)
        if record is None:
            continue
        if record["event_type"] in _DNS_BEARING_EVENT_TYPES:
            return "dns"
    return None
