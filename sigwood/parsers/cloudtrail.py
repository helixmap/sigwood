"""CloudTrail event parsing - normalize raw AWS events into canonical row dicts.

Provides pure parsing functions with no file I/O. File discovery, decompression,
NDJSON / envelope sniffing, DataFrame construction, and timeframe filtering are
handled by loader.py via load_cloudtrail().

Per-event normalization, not aggregation. The aws detector aggregates per-principal
on the back end - the same parser-emits-fragments / detector-aggregates split that
dnsmasq uses (`_build_pihole_aggregate` lives in the detector, not the parser).

Canonical CloudTrail event schema (v1)
──────────────────────────────────────
parse_event() emits one dict per event with these twelve keys, all always present.

Carried fields (verbatim from the wire event, or None when absent):
  ts            - eventTime parsed to unix epoch float; None when missing/garbage
  event_source  - eventSource (full string, e.g. "s3.amazonaws.com")
  event_name    - eventName (e.g. "ListBuckets")
  identity_type - userIdentity.type (IAMUser, AssumedRole, AWSService, Root, …)
  source_ip     - sourceIPAddress
  error_code    - errorCode; None means the call succeeded
  aws_region    - awsRegion - human-triage pivot
  event_id      - eventID - drill-back anchor; the analyst's key to the full event

Derived fields (computed from one or more wire fields by the rules below):
  principal     - stable per-actor key; collapses userIdentity variants so a role
                  assumed many times is one actor, not many. See _derive_principal.
  lane          - "interactive" | "service", mechanically derived from
                  userIdentity.type / invokedBy / service-linked-role naming
  read_write    - "read" | "write"; top-level readOnly when present, else inferred
                  from the action verb (handles thinner old event schemas)

Escape hatch (SCHEMA.md → promote-don't-grep):
  raw           - original event dict, unmodified. No v1 detector reads this at
                  runtime. Future detectors that need fields living in `raw` -
                  recipient_account_id, user_agent, requestParameters,
                  responseElements, resources - promote them to real, typed,
                  documented canonical columns at that time, with real knowledge
                  of what the signal needs. Detectors never reach into `raw`
                  mid-analysis.

Adding a carried column later is a one-line, obvious change: add the key to the
single result-dict literal in parse_event(), pulled with .get(...).
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

# Verb-inference fallback for read_write - used only when an event has no top-level
# readOnly field (older CloudTrail event schemas). A prefix match in this set maps
# the event to "read"; everything else is "write".
_READ_VERB_PREFIXES: tuple[str, ...] = (
    "Get", "List", "Describe", "Head", "Lookup",
    "Search", "BatchGet", "Select", "Query", "Scan",
)


def parse_event(event: Any) -> dict | None:
    """Parse a raw CloudTrail event dict into the canonical row dict.

    Returns None only when ``event`` is not a dict. For any dict input, returns
    a row with all twelve canonical keys present - never raises on missing,
    malformed, or unexpected fields anywhere in the event. All sub-lookups are
    defensive: missing nested objects degrade to the appropriate field-level
    fallback rather than aborting the parse.
    """
    if not isinstance(event, dict):
        return None

    user_identity = event.get("userIdentity")
    identity_type = user_identity.get("type") if isinstance(user_identity, dict) else None

    return {
        "ts":            _parse_event_time(event.get("eventTime")),
        "principal":     _derive_principal(user_identity),
        "lane":          _derive_lane(user_identity),
        "read_write":    _derive_read_write(event),
        "event_source":  event.get("eventSource"),
        "event_name":    event.get("eventName"),
        "identity_type": identity_type,
        "source_ip":     event.get("sourceIPAddress"),
        "error_code":    event.get("errorCode"),
        "aws_region":    event.get("awsRegion"),
        "event_id":      event.get("eventID"),
        "raw":           event,
    }


# ── Derivation helpers ────────────────────────────────────────────────────────

def _parse_event_time(s: Any) -> float | None:
    """Parse an ISO 8601 eventTime string to unix epoch float; None on failure.

    Mirrors exporters/cloudtrail.py:_parse_event_time. CloudTrail emits "Z" suffix
    UTC; fromisoformat handles a "+00:00" offset, hence the substitution.
    """
    if not isinstance(s, str) or not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _derive_principal(user_identity: Any) -> str:
    """Derive a stable per-actor key from userIdentity.

    Central intent: a role assumed many times is one actor. AssumedRole events
    key on the session *issuer*, not the per-assumption session name, so every
    session of one role aggregates together. See SCHEMA.md for the full rule.
    """
    if not isinstance(user_identity, dict):
        return "unknown"

    itype = user_identity.get("type")

    if itype == "AssumedRole":
        session_context = user_identity.get("sessionContext")
        if isinstance(session_context, dict):
            issuer = session_context.get("sessionIssuer")
            if isinstance(issuer, dict):
                user_name = issuer.get("userName")
                if isinstance(user_name, str) and user_name:
                    return user_name
                arn = issuer.get("arn")
                if isinstance(arn, str) and arn:
                    last = arn.rsplit("/", 1)[-1]
                    if last:
                        return last
                issuer_pid = issuer.get("principalId")
                if isinstance(issuer_pid, str) and issuer_pid:
                    return issuer_pid
        # fall through to generic fallback when sessionIssuer is absent/empty

    elif itype == "IAMUser":
        user_name = user_identity.get("userName")
        if isinstance(user_name, str) and user_name:
            return user_name
        arn = user_identity.get("arn")
        if isinstance(arn, str) and arn:
            last = arn.rsplit("/", 1)[-1]
            if last:
                return last
        # principalId is the next step, handled by the generic fallback below

    elif itype == "AWSService":
        invoked_by = user_identity.get("invokedBy")
        if isinstance(invoked_by, str) and invoked_by:
            return invoked_by
        # fall through to generic fallback

    elif itype == "Root":
        return "root"

    # Generic fallback: federated/SAML/WebIdentity/IdentityCenter/AWSAccount/unknown
    # types, plus fall-through from the per-type branches above when their preferred
    # fields are missing. principalId stability is what keeps two distinct actors
    # under an unknown type from collapsing into one bucket.
    pid = user_identity.get("principalId")
    if isinstance(pid, str) and pid:
        return pid
    if isinstance(itype, str) and itype:
        return itype
    return "unknown"


def _derive_lane(user_identity: Any) -> str:
    """Return "service" or "interactive" for an event's userIdentity.

    Mechanical, no security judgment. "service" if any of:
      1. userIdentity.type is AWSService or AWSAccount
      2. userIdentity.invokedBy ends with "amazonaws.com"
      3. "AWSServiceRoleFor" appears in userIdentity.arn or
         sessionContext.sessionIssuer.arn

    Otherwise "interactive". No hardcoded principal-name list - corpus-specific
    role names are not a parser concern.
    """
    if not isinstance(user_identity, dict):
        return "interactive"

    itype = user_identity.get("type")
    if itype in ("AWSService", "AWSAccount"):
        return "service"

    invoked_by = user_identity.get("invokedBy")
    if isinstance(invoked_by, str) and invoked_by.endswith("amazonaws.com"):
        return "service"

    arn = user_identity.get("arn")
    if isinstance(arn, str) and "AWSServiceRoleFor" in arn:
        return "service"

    session_context = user_identity.get("sessionContext")
    if isinstance(session_context, dict):
        issuer = session_context.get("sessionIssuer")
        if isinstance(issuer, dict):
            issuer_arn = issuer.get("arn")
            if isinstance(issuer_arn, str) and "AWSServiceRoleFor" in issuer_arn:
                return "service"

    return "interactive"


def _derive_read_write(event: dict) -> str:
    """Return "read" or "write" from top-level readOnly, else verb inference.

    readOnly precedence: boolean True / string "true" → "read"; boolean False /
    string "false" → "write". Absent readOnly falls back to the action verb:
    eventName starting with a known read prefix → "read", else "write".
    """
    read_only = event.get("readOnly")
    if read_only is True:
        return "read"
    if read_only is False:
        return "write"
    if isinstance(read_only, str):
        lowered = read_only.lower()
        if lowered == "true":
            return "read"
        if lowered == "false":
            return "write"

    # readOnly absent or in an unrecognised shape - verb inference fallback.
    name = event.get("eventName")
    if isinstance(name, str) and name:
        for prefix in _READ_VERB_PREFIXES:
            if name.startswith(prefix):
                return "read"
    return "write"


SNIFF_PEEK_LINES: int = 200

# Quoted-key + colon - matches a JSON key declaration, not a value substring.
_CT_KEY_RE: dict[str, re.Pattern[str]] = {
    "Records":      re.compile(r'"Records"\s*:'),
    "eventVersion": re.compile(r'"eventVersion"\s*:'),
    "eventTime":    re.compile(r'"eventTime"\s*:'),
    "userIdentity": re.compile(r'"userIdentity"\s*:'),
}

_CT_EVENT_KEYS: tuple[str, ...] = ("eventVersion", "eventTime", "userIdentity")


def sniff(sample: list[str]) -> str | None:
    """Recognize CloudTrail JSON (NDJSON event or envelope) and return "cloudtrail".

    Two paths, either one wins:

    1. NDJSON: the first non-empty line parses as a dict containing at least
       two of ``eventVersion``, ``eventTime``, ``userIdentity``.
    2. Envelope (structural - does not require the sample to contain a
       parseable JSON document): the joined sample contains the quoted key
       ``"Records":`` AND at least two of the three per-event keys
       (``"eventVersion":``, ``"eventTime":``, ``"userIdentity":``) as
       quoted-key tokens. Survives pretty-printed envelopes whose first
       record exceeds the sample budget.

    Returns None when neither path matches.

    Pure: takes already-decoded lines, performs no I/O.
    """
    for raw_line in sample:
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError, RecursionError):
            break
        if isinstance(obj, dict):
            hit = sum(1 for k in _CT_EVENT_KEYS if k in obj)
            if hit >= 2:
                return "cloudtrail"
        break

    joined = "\n".join(sample)
    if _CT_KEY_RE["Records"].search(joined):
        hit = sum(1 for k in _CT_EVENT_KEYS if _CT_KEY_RE[k].search(joined))
        if hit >= 2:
            return "cloudtrail"
    return None
