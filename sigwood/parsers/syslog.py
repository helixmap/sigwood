"""RFC 3164 and ISO-8601 syslog parsing for detector analysis.

Provides pure parsing functions with no file I/O. File discovery and DataFrame
construction are handled by loader.py. The syslog detector operates on the
normalized output produced here via load_syslog().
"""

import re
from datetime import datetime, timedelta, timezone

# ── Compiled patterns ─────────────────────────────────────────────────────────

PRI_RE        = re.compile(r'^<\d+>')
SYSLOG_HDR_RE = re.compile(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+')
PROC_PID_RE   = re.compile(r'\[\d+\]')

# ISO-8601 / RFC-3339 syslog stamps carry a year and explicit offset. The
# parse, strip, and discovery patterns share one timestamp fragment while
# retaining role-specific header strictness.
_ISO_TS = (
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)"
)
ISO_TS_RE = re.compile(rf"^{_ISO_TS}(?=\s|$)")
ISO_HDR_RE = re.compile(rf"^{_ISO_TS}\s+\S+\s+")
ISO_SNIFF_RE = re.compile(rf"^{_ISO_TS}\s+\S+\s+\S+:(?=\s|$)")

# Program/process token at the head of a header-stripped syslog body.
# Matches the leading run of non-whitespace characters up to the first '[' or ':'.
PROGRAM_RE    = re.compile(r'^[^\[:\s]+')

# Timestamp in position 0-2 after stripping PRI (month day HH:MM:SS)
SYSLOG_TS_RE  = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})')

# Reboot signal patterns - any match triggers reboot detection in the detector.
# The kernel boot banner appears with OR without a ring-buffer ts prefix
# (`kernel: [    0.000000] Linux version …`), so the bracket is optional.
REBOOT_SIGNALS_RE = re.compile(
    r'(?:systemd-logind.*[Ss]ystem is rebooting|'
    r'rsyslogd.*exiting on signal 15|'
    r'systemd-shutdown.*Sending SIGTERM to remaining|'
    r'kernel:\s*(?:\[\s*[0-9.]+\]\s*)?Linux version\s)',
    re.IGNORECASE,
)


# ── Parsing functions ─────────────────────────────────────────────────────────

def parse_host(raw: str) -> str:
    """Extract the hostname from an RFC 3164 or ISO-8601 syslog line.

    ISO-8601 uses field 2 because its timestamp is one token; RFC 3164 uses
    field 4 because its timestamp is three tokens. Returns ``"unknown"`` when
    the selected layout is too short to contain a hostname.
    """
    stripped = PRI_RE.sub("", raw).strip()
    parts = stripped.split()
    if ISO_TS_RE.match(stripped):
        return parts[1] if len(parts) >= 2 else "unknown"
    return parts[3] if len(parts) >= 4 else "unknown"


def strip_header(raw: str) -> str:
    """Remove the optional PRI and supported timestamp/hostname header."""
    raw = PRI_RE.sub("", raw)
    body = SYSLOG_HDR_RE.sub("", raw)
    if body == raw:
        body = ISO_HDR_RE.sub("", raw)
    return body.strip()


def normalize_pids(msg: str) -> str:
    """Collapse process PID brackets so sshd[1234] and sshd[5678] share a template."""
    return PROC_PID_RE.sub("[*]", msg)


def parse_program(body: str) -> str:
    """Extract the program/process token from a header-stripped syslog body.

    Strips surrounding whitespace, then returns the leading run of
    non-whitespace characters up to the first '[' or ':' (e.g. 'sshd',
    'postfix/smtpd', 'kernel'). Returns 'unknown' when no such token exists
    (empty body after stripping, or first non-whitespace character is '[' or ':').
    """
    m = PROGRAM_RE.match(body.strip())
    return m.group(0) if m else "unknown"


def strip_program(body: str) -> str:
    """Remove a leading syslog program tag and return its message body.

    The accepted tag uses the same program-token grammar as ``parse_program``
    and may carry one bracketed process suffix before the required colon.
    Bodies without that complete prefix are returned unchanged after stripping.
    """
    stripped = body.strip()
    match = PROGRAM_RE.match(stripped)
    if match is None:
        return stripped

    remainder = stripped[match.end():]
    if remainder.startswith("["):
        bracket_end = remainder.find("]")
        if bracket_end < 0:
            return stripped
        remainder = remainder[bracket_end + 1:]
    if not remainder.startswith(":"):
        return stripped
    return remainder[1:].strip()


def parse_timestamp(raw: str) -> datetime | None:
    """Parse an RFC 3164 or aware ISO-8601 timestamp to UTC.

    ISO-8601 timestamps carry a year and explicit offset, so they convert
    directly to UTC without wall-clock inference.

    An RFC 3164 wall-clock is interpreted as HOST-LOCAL time - the timezone
    rsyslog and dnsmasq write in - and converted to true UTC on return (DST
    gap/fold edges take the stdlib's naive-astimezone defaults). RFC 3164
    carries no year: the current local year is the starting point, with a
    rollback heuristic - a result more than 7 days in the future belongs to
    the previous year.

    Returns None if the line contains no parseable timestamp.
    """
    stripped = PRI_RE.sub("", raw).strip()
    if ISO_TS_RE.match(stripped):
        token = stripped.split(maxsplit=1)[0]
        try:
            iso_dt = datetime.fromisoformat(token)
        except ValueError:
            pass
        else:
            if iso_dt.tzinfo is not None:
                return iso_dt.astimezone(timezone.utc)

    m = SYSLOG_TS_RE.match(stripped)
    if not m:
        return None
    month_str, day_str, time_str = m.group(1), m.group(2), m.group(3)
    year = datetime.now().year
    try:
        dt = datetime.strptime(
            f"{year} {month_str} {day_str.zfill(2)} {time_str}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None
    if dt > datetime.now() + timedelta(days=7):
        dt = dt.replace(year=dt.year - 1)
    return dt.astimezone(timezone.utc)


def is_reboot_signal(raw: str) -> bool:
    """Return True if the raw line matches a known reboot or shutdown pattern."""
    return bool(REBOOT_SIGNALS_RE.search(raw))


def parse_line(raw: str) -> dict | None:
    """Parse a raw syslog line into a normalized record dict.

    Returns None for blank lines and comment lines (starting with #).
    Returns a dict with keys: ts (datetime | None), host (str), program (str),
    raw (str), message (str). Empty message strings are preserved - the caller
    decides whether to filter them.
    """
    if not raw or raw.lstrip().startswith("#"):
        return None
    body = strip_header(raw)
    return {
        "ts":      parse_timestamp(raw),
        "host":    parse_host(raw),
        "program": parse_program(body),
        "raw":     raw,
        "message": normalize_pids(body),
    }


SNIFF_PEEK_LINES: int = 32


def sniff(sample: list[str]) -> str | None:
    """Recognize an RFC 3164 or ISO-8601 syslog line and return "syslog".

    Real-header signal - not "parse_line non-None" (which is true for any
    nonblank line). Requires BOTH a supported transport shape and a parseable
    timestamp. RFC 3164 uses its distinctive timestamp/host header. ISO-8601
    additionally requires a non-empty, colon-terminated program tag because
    aware ISO stamps are common in non-syslog application logs.

    An ISO line without a program tag does not anchor discovery, but it still
    parses once another line in the sampled file proves the stream's identity.

    Returns "syslog" on the first line that passes both checks. Returns
    None when the budget is exhausted with no real-header line - garbage
    text, prose, and blank-only samples fall through correctly.

    Pure: takes already-decoded lines, performs no I/O.
    """
    for raw_line in sample:
        if not raw_line or raw_line.lstrip().startswith("#"):
            continue
        stripped = PRI_RE.sub("", raw_line).lstrip()
        if not (
            SYSLOG_HDR_RE.match(stripped) or ISO_SNIFF_RE.match(stripped)
        ):
            continue
        if parse_timestamp(raw_line) is None:
            continue
        return "syslog"
    return None
