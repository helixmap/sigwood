"""First-run setup wizard.

CLI-INTERNAL split off ``sigwood/cli.py`` - first-run UX REMAINS CLI-layer
ownership. This module owns the wizard; ``cli.py`` keeps dispatch and arg
validation. Nothing here imports detectors, runner, or outputs.

The wizard mostly works by hitting Enter: it LOOKS before it asks (detect +
profile what's on disk), is DEFAULT-DRIVEN (an existing config seeds the
prompts, never re-detected from scratch), and NEVER clobbers config a user
already set. Path profiling is glob + stat only except for syslog's bounded
RFC-3164 / ISO-8601 shape sniff; init never displays, stores, summarizes, or
extracts log content. No filesystem mutation happens before the change-summary
is accepted, so abort and redo truthfully change nothing.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import re
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

# Sanctioned pure stdlib-only leaves. Path/root resolution, bounded journal
# capability, and system-log mode classification each keep one owner. No
# detector/runner/output/loader/config imports.
import sigwood.common.journal_probe as journal_probe
import sigwood.common.syslog_mode as syslog_mode
from sigwood.common.paths import (
    effective_root,
    private_mkdir,
    private_open,
    private_write_bytes,
    private_write_text,
    resolve_path,
)

# ── detection ─────────────────────────────────────────────────────────────────
#
# Detection looks at conventional public paths. Source profiling is stat/glob
# only except for syslog's bounded RFC-3164 / ISO-8601 format sniff; no content
# is ever displayed, stored, summarized, or extracted. Constants are module-
# level so flow tests can monkeypatch them off the developer's real filesystem.

_ZEEK_CANDIDATES: tuple[str, ...] = (
    "/var/log/zeek",
    "/opt/zeek/logs",
    "/usr/local/zeek/logs",
    "/nsm/zeek/logs",
)
# Each entry: (probe path, candidate_dir to register if probe matches). The
# probe may be a literal file or an absolute glob ("/dir/*.log").
_PIHOLE_CANDIDATES: tuple[tuple[str, str], ...] = (
    ("/var/log/pihole/pihole.log", "/var/log/pihole"),
    ("/var/log/pihole.log",        "/var/log"),
    ("/var/log/pihole/pihole*.log*", "/var/log/pihole"),
)
_SYSLOG_CANDIDATE: str = "/var/log"

# Zeek family globs drive the {logs} fill and the size sum. `syslog*.log*` is
# included because the syslog detector consumes `zeek_dir: syslog*.log*`, so a
# Zeek tree that keeps only syslog.log must still classify as Zeek (the primary-
# name filter passes Zeek's syslog.log but not a flat auth.log/kern.log, whose
# stem is not "syslog").
_ZEEK_GLOBS: tuple[str, ...] = (
    "conn*.log*", "dns*.log*", "ssl*.log*",
    "http*.log*", "weird*.log*", "notice*.log*", "syslog*.log*",
)
# Dated-rotation child classification (YYYY-MM-DD prefix, immediate
# children). Mirrors the loader's dated-layout rule - cli_init cannot import
# the loader (stdlib-only boundary), so the pattern is mirrored here and a
# drift test pins the two strings together.
_ZEEK_DATE_DIR_RE: re.Pattern[str] = re.compile(r"^\d{4}-\d{2}-\d{2}")
# Pi-hole stays narrow even when the candidate dir is /var/log - we profile
# only the Pi-hole files so unrelated syslog files don't inflate the size. The
# glob mirrors the runtime Pi-hole pattern OWNED by the DNS detector
# (dns.OPTIONAL_LOGS, the pihole_dir entry); a drift tripwire pins the agreement.
_PIHOLE_GLOB: str = "pihole*.log*"
# Syslog profiles by the bounded content head sniff below, not by this glob.
# The glob remains the detector/source key shape shown elsewhere.
_SYSLOG_GLOB: str = "*.log*"
# CloudTrail is opt-in (never detected); a CONFIGURED value is profiled with
# this glob so re-init previews the JSON envelopes already on disk.
_CLOUDTRAIL_GLOB: str = "*.json*"

_PROFILE_FILE_CAP: int = 5000
_DOCS_URL: str = "https://github.com/helixmap/sigwood"
_SYSLOG_SNIFF_BYTES: int = 8192
_SYSLOG_SNIFF_PEEK_LINES: int = 32
_SYSLOG_PRI_RE: re.Pattern[str] = re.compile(r"^<\d+>")
_SYSLOG_HDR_RE: re.Pattern[str] = re.compile(
    r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
)
_SYSLOG_TS_RE: re.Pattern[str] = re.compile(
    r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})"
)
_ISO_TS: str = (
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)"
)
_ISO_TS_RE: re.Pattern[str] = re.compile(rf"^{_ISO_TS}(?=\s|$)")
_ISO_SNIFF_RE: re.Pattern[str] = re.compile(
    rf"^{_ISO_TS}\s+\S+\s+\S+:(?=\s|$)"
)

# The sigwood HOMEs, in discovery precedence - a CALL-TIME mirror of
# cfg.SEARCH_PATHS' parents (user-home wins over system). Kept call-time (and
# monkeypatchable) because cfg.SEARCH_PATHS is computed once at import and would
# not honor a test's HOME isolation. A drift tripwire asserts agreement with
# cfg.SEARCH_PATHS. The config target is always <home>/config.toml.
_SEARCH_HOMES: tuple[str, ...] = ("~/.sigwood", "/etc/sigwood")

# Flat allowlist drop-in templates seeded into <home>/allowlist.d on a fresh
# init (and re-seeded on reset-allowlist). Curated lists are NOT copied.
_ALLOWLIST_SEED_FILES: tuple[str, ...] = ("domains_user", "connections")

_DEFAULT_ROOT: str = "~/.sigwood"
_SYSTEM_ROOT: str = "/etc/sigwood"
_DEFAULT_SYSLOG_DIR: str = "/var/log"

# Shared HOME MENU leads - the option parser/renderer is shared, the LEAD differs
# by caller so copy never advertises an action the caller can't perform: the fresh
# location picks the config HOME + root; the unset-root menu sets the data ROOT
# only (the config path is fixed there - do NOT imply moving it).
_FRESH_LOCATION_LEAD: str = (
    "Where should sigwood live - its config, exports, and reports?"
)
_UNSET_ROOT_LEAD: str = (
    "root isn't set - where should sigwood store exports and reports?"
)


def _is_primary_zeek_name(name: str, pattern: str) -> bool:
    """Return True if name is the primary Zeek log for pattern (rotations included),
    not a derived sibling that merely shares the type prefix (conn-summary,
    conn_history). A primary log's stem before the first '.' equals the log type;
    Zeek rotation only ever inserts a '.' (conn.<ts>.log), never '-' or '_'. Mirrors
    the loader's classifier - cli_init cannot import the loader (stdlib-only boundary),
    so the rule is mirrored here and a drift test pins the two behaviors together."""
    log_type = pattern.split("*", 1)[0]
    if not log_type:
        return True  # non-type-anchored pattern (defensive): no narrowing
    return name.split(".", 1)[0] == log_type


def _classify_dropin(name: str) -> str | None:
    """Stdlib MIRROR of allowlist._classify_dropin - cli_init cannot import
    common/allowlist (stdlib-only boundary), so the dot rule is mirrored here and a
    drift test pins the two identical. Classify an allowlist.d entry BY NAME:
    "domain" | "numeric" | "stanza" | None. Clause order IS the spec. The reset
    deleter reads this to unlink only files classifying "domain" / "numeric"."""
    if name.startswith("."):        # hidden
        return None
    if name.endswith("~"):          # editor backup
        return None
    if name.endswith(".toml"):      # a dot naming a parsed format
        return "stanza"
    if "." in name:                 # any other dot: ignored
        return None
    if name.startswith("domains"):
        return "domain"
    if name.startswith("connections"):
        return "numeric"
    return None


def _open_log_head(path: Path):
    """Open a plain or suffix-compressed log head using loader-compatible codecs."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.suffix == ".bz2":
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if path.suffix == ".xz":
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _syslog_ts_parseable(line: str) -> bool:
    """Return True when the RFC-3164 timestamp prefix is calendar-parseable."""
    stripped = _SYSLOG_PRI_RE.sub("", line).strip()
    match = _SYSLOG_TS_RE.match(stripped)
    if not match:
        return False
    month, day, time_s = match.groups()
    try:
        datetime.strptime(
            f"{datetime.now().year} {month} {day.zfill(2)} {time_s}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return False
    return True


def _iso_ts_parseable(line: str) -> bool:
    """Return True when the ISO-8601 timestamp prefix is offset-aware."""
    stripped = _SYSLOG_PRI_RE.sub("", line).strip()
    if not _ISO_TS_RE.match(stripped):
        return False
    token = stripped.split(maxsplit=1)[0]
    try:
        parsed = datetime.fromisoformat(token)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _looks_like_syslog_head(path: Path) -> bool:
    """Bounded stdlib mirror of the loader's flat-syslog content gate."""
    try:
        with _open_log_head(path) as fh:
            chunk = fh.read(_SYSLOG_SNIFF_BYTES)
    except (EOFError, gzip.BadGzipFile, lzma.LZMAError, OSError):
        return True
    if "\x00" in chunk:
        return False
    for raw_line in chunk.splitlines()[:_SYSLOG_SNIFF_PEEK_LINES]:
        if not raw_line or raw_line.lstrip().startswith("#"):
            continue
        stripped = _SYSLOG_PRI_RE.sub("", raw_line).lstrip()
        if (
            _SYSLOG_HDR_RE.match(stripped)
            and _syslog_ts_parseable(raw_line)
        ) or (
            _ISO_SNIFF_RE.match(stripped)
            and _iso_ts_parseable(raw_line)
        ):
            return True
    return False


def _syslog_profile_files(
    path: Path,
    head_sniff: Callable[[Path], bool],
    *,
    limit: int | None = None,
) -> list[Path]:
    """Return the syslog files the loader's directory discovery would accept."""
    matched: list[Path] = []
    for f in sorted(path.iterdir(), key=lambda p: p.name):
        if not f.is_file() or f.name.startswith("._"):
            continue
        if not head_sniff(f):
            continue
        matched.append(f)
        if limit is not None and len(matched) >= limit:
            break
    return matched


def _zeek_profile_files(path: Path, pattern: str) -> list[Path]:
    """Return Zeek profile candidates using the loader's flat/dated layout depth."""
    date_dirs = [
        c for c in path.iterdir()
        if c.is_dir() and _ZEEK_DATE_DIR_RE.match(c.name)
    ]
    if not date_dirs:
        return [
            f for f in sorted(path.glob(pattern))
            if _is_primary_zeek_name(f.name, pattern)
        ]

    non_date_children = [
        c for c in path.iterdir()
        if c.is_dir() and not _ZEEK_DATE_DIR_RE.match(c.name)
    ]
    seen: set[Path] = set()
    included: list[Path] = []
    for child in sorted([*date_dirs, *non_date_children], key=lambda p: p.name):
        try:
            resolved = child.resolve()
        except OSError:
            resolved = child
        if resolved in seen:
            continue
        seen.add(resolved)
        included.append(child)

    files: list[Path] = []
    for child in included:
        files.extend(
            f for f in sorted(child.glob(pattern))
            if _is_primary_zeek_name(f.name, pattern)
        )
    return files


def _detect_zeek() -> str | None:
    """Probe conventional Zeek log dirs. A candidate is classified by
    layout the way the loader classifies it: dated when any immediate
    child is date-named (YYYY-MM-DD), else flat. A flat candidate hits on
    top-level conn*.log*; a dated candidate hits one level down - where
    zeekctl keeps logs (date dirs plus the current/ spool) - and its
    root-level files count for nothing, because the loader's dated
    discovery ignores them. First conn hit wins; else the first candidate
    with any primary Zeek-family log at its layout's depth. A root holding
    only derived siblings (conn-summary) or only non-family logs (files, x509)
    does not classify as Zeek - the hunt would load nothing there. Returns the
    dir path or None."""
    fallback: str | None = None
    for cand in _ZEEK_CANDIDATES:
        p = Path(cand)
        try:
            if not p.is_dir():
                continue
            top_conn = any(
                _is_primary_zeek_name(f.name, "conn*.log*")
                for f in p.glob("conn*.log*")
            )
            dated = any(
                c.is_dir() and _ZEEK_DATE_DIR_RE.match(c.name)
                for c in p.iterdir()
            )
            if not dated:
                if top_conn:
                    return cand
                if fallback is None and any(
                    _is_primary_zeek_name(f.name, g)
                    for g in _ZEEK_GLOBS
                    for f in p.glob(g)
                ):
                    fallback = cand
            else:
                # Mixed-root parity: with a date-named child present the
                # loader reads the tree as dated and ignores root-level
                # files, so a top-level hit must not advertise the
                # candidate - only one-level child hits count. Depth is
                # exactly one level because dated discovery reads
                # immediate children only.
                if any(
                    _is_primary_zeek_name(f.name, "conn*.log*")
                    for f in p.glob("*/conn*.log*")
                ):
                    return cand
                if fallback is None and any(
                    _is_primary_zeek_name(f.name, g)
                    for g in _ZEEK_GLOBS
                    for f in p.glob("*/" + g)
                ):
                    fallback = cand
        except OSError:
            continue
    return fallback


def _detect_pihole() -> str | None:
    """Walk pi-hole probes; return the candidate dir of the first hit."""
    for probe, candidate_dir in _PIHOLE_CANDIDATES:
        try:
            if "*" in probe:
                # Path.glob walks the receiver - for an absolute glob we must
                # split (parent, pattern) and glob from the parent directory.
                parent = Path(probe).parent
                pattern = Path(probe).name
                if parent.is_dir() and any(parent.glob(pattern)):
                    return candidate_dir
            else:
                if Path(probe).is_file():
                    return candidate_dir
        except OSError:
            continue
    return None


def _detect_syslog() -> str | None:
    """Return the syslog candidate dir when at least one file sniffs as syslog."""
    try:
        candidate = Path(_SYSLOG_CANDIDATE)
        if not candidate.is_dir():
            return None
        return (
            _SYSLOG_CANDIDATE
            if _syslog_profile_files(candidate, _looks_like_syslog_head, limit=1)
            else None
        )
    except OSError:
        return None


def _human_bytes(n: int) -> str:
    """Format a byte count as `~6 GB` / `~340 MB` / `~12 KB`. The `~` reflects
    that the count is glob-scoped, not whole-dir."""
    if n < 1024:
        return f"~{n} B"
    if n < 1024 ** 2:
        return f"~{n // 1024} KB"
    if n < 1024 ** 3:
        return f"~{n // (1024 ** 2)} MB"
    if n < 1024 ** 4:
        return f"~{n // (1024 ** 3)} GB"
    return f"~{n // (1024 ** 4)} TB"


def _fresh_bucket(delta: timedelta) -> str:
    """Map an age delta to a relative-time phrase."""
    seconds = delta.total_seconds()
    if seconds < 3600:
        return "updated just now"
    if seconds < 86_400:
        return "fresh today"
    if seconds < 7 * 86_400:
        return "active this week"
    days = int(seconds // 86_400)
    if seconds < 30 * 86_400:
        return f"last activity ~{days} days ago"
    if seconds < 60 * 86_400:
        weeks = days // 7
        return f"but it looks stale - nothing new in ~{weeks} weeks"
    months = days // 30
    return f"but it looks stale - nothing new in ~{months} months"


def _profile_dir(
    path: str,
    globs: tuple[str, ...],
    *,
    logs_label: str | None,
    recursive: bool = False,
    head_sniff: Callable[[Path], bool] | None = None,
    zeek_layout: bool = False,
    now: datetime | None = None,
) -> dict | None:
    """Stat + glob the candidate dir; return a profile dict or None (no-data).

    Permission-tolerant: a single file's stat raising OSError is silently
    skipped. The dir not existing or no files matching returns None - the
    caller's "reduced dialogue form" branch."""
    p = Path(path).expanduser()
    try:
        if not p.is_dir():
            return None
    except OSError:
        return None

    matched: list[Path] = []
    families_present: list[str] = []  # zeek family order, first-seen
    bounded = False
    try:
        if head_sniff is not None:
            matched = _syslog_profile_files(p, head_sniff, limit=_PROFILE_FILE_CAP)
            bounded = len(matched) >= _PROFILE_FILE_CAP
        for glob in () if head_sniff is not None else globs:
            family = glob.split("*", 1)[0].rstrip(".")  # "conn*.log*" → "conn"
            family_hit = False
            # Zeek uses the loader-depth flat/dated walk; CloudTrail is the
            # only unbounded recursive profile because native AWSLogs trees
            # can be nested several levels deep. Flat sources stay flat.
            if zeek_layout:
                walker = _zeek_profile_files(p, glob)
            else:
                walker = p.rglob(glob) if recursive else p.glob(glob)
            for f in walker:
                # Zeek-family globs count primary logs only, matching what the
                # loader loads; a derived sibling (conn-summary) is not a log.
                # The pihole/syslog globs are not Zeek-family and stay unfiltered.
                if glob in _ZEEK_GLOBS and not _is_primary_zeek_name(f.name, glob):
                    continue
                matched.append(f)
                family_hit = True
                if len(matched) >= _PROFILE_FILE_CAP:
                    bounded = True
                    break
            if family_hit and family and family not in families_present:
                families_present.append(family)
            if bounded:
                break
    except OSError:
        return None

    total = 0
    max_mtime: float | None = None
    for f in matched:
        try:
            st = f.stat()
        except OSError:
            continue
        total += st.st_size
        if max_mtime is None or st.st_mtime > max_mtime:
            max_mtime = st.st_mtime

    if not matched or total == 0 or max_mtime is None:
        return None

    now = now or datetime.now()
    delta = now - datetime.fromtimestamp(max_mtime)

    if logs_label is not None:
        logs = logs_label
    elif families_present:
        if len(families_present) <= 2:
            logs = " + ".join(families_present)
        else:
            logs = ", ".join(families_present)
    else:
        logs = ""

    return {
        "size_bytes": total,
        "size_str": _human_bytes(total),
        "fresh_str": _fresh_bucket(delta),
        "logs": logs,
        "bounded": bounded,
    }


def _render_profile(profile: dict) -> str:
    """Render a profile dict as the uniform headline dash-text - the non-empty
    of [logs, size, freshness] joined with ", ". Zeek → "conn + dns, ~340 MB,
    fresh today"; Pi-hole → "query logs, ~12 MB, active this week"; syslog (no
    family label) → "~340 MB, fresh today"."""
    parts = [profile["logs"], profile["size_str"], profile["fresh_str"]]
    return ", ".join(p for p in parts if p)


# ── TOML serialization ────────────────────────────────────────────────────────

_TOML_FORBIDDEN_RE = re.compile(r'[\x00-\x1f\x7f]')


def _toml_str(value: str) -> str:
    """Serialize a path value as a double-quoted TOML BASIC string, matching the
    shipped example/comments. Backslash and double-quote are escaped; control
    characters are rejected - silently writing invalid TOML is worse than asking
    the user to retype the path."""
    if _TOML_FORBIDDEN_RE.search(value):
        raise ValueError(
            "path contains a control character that cannot "
            f"be written to TOML: {value!r}"
        )
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


# ── Section-bound keyed upsert ────────────────────────────────────────────────
#
# The six managed keys
# are rewritten ONLY inside the [sigwood] table span. A token appearing in any
# other stanza, a comment outside the span, or even a [sigwood.subtable] is
# never matched - that IS the non-clobber guarantee.

_SIGWOOD_HEADER_RE = re.compile(r'^\[sigwood\]\s*(?:#.*)?$', re.MULTILINE)
_MANAGED_KEYS: tuple[str, ...] = (
    "root", "zeek_dir", "pihole_dir", "syslog_dir", "cloudtrail_dir",
    "syslog_source",
)


def _sigwood_span(text: str) -> tuple[int, int, int] | None:
    """Locate the [sigwood] table span: (header_start, body_start, body_end).

    body runs from the line AFTER the header to the line BEFORE the next
    `^[` section header, or EOF. Returns None when the header is absent."""
    m = _SIGWOOD_HEADER_RE.search(text)
    if m is None:
        return None
    header_start = m.start()
    # body starts after the header line's trailing newline
    nl = text.find("\n", m.end())
    body_start = nl + 1 if nl != -1 else len(text)
    # body ends at the next ^[ section header found after body_start
    rest_offset = body_start
    next_header_re = re.compile(r'^\[', re.MULTILINE)
    nh = next_header_re.search(text, rest_offset)
    body_end = nh.start() if nh else len(text)
    return (header_start, body_start, body_end)


def _inline_comment(active_line: str) -> str:
    """Return the trailing inline comment (``# …``) of a managed-key line, or "".

    Scans the value (after the first ``=``), respecting TOML string quoting so a
    ``#`` inside a quoted path is not mistaken for a comment. Used to PRESERVE a
    user's inline comment when a keep/change rewrites the active line - the
    re-quote (single→double) is intended; dropping the comment is not."""
    _, _, rhs = active_line.partition("=")
    in_str: str | None = None
    i = 0
    while i < len(rhs):
        c = rhs[i]
        if in_str is not None:
            if in_str == '"' and c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
        elif c in ('"', "'"):
            in_str = c
        elif c == "#":
            return rhs[i:].rstrip()
        i += 1
    return ""


def _upsert_sigwood_key(
    text: str, key: str, value: str | None, *, fresh: bool,
) -> str:
    """Keyed transform inside the [sigwood] table span.

    value is None        - COMMENT. fresh=True comments any active line for the
                            key (the `remove` action's revert-to-default); fresh=False
                            is a strict no-op (never touch a user-set value). A skip
                            disables a source through `_disable_sigwood_key`, not here.
    value is a string    - PROVIDED. Upsert active line inside span. value=""
                            is honored (the explicit-empty-root case).
    """
    span = _sigwood_span(text)
    if span is None:
        # Defensive - the shipped example always ships a header. Prepend one
        # so the upsert has a place to land.
        text = "[sigwood]\n" + text
        span = _sigwood_span(text)
        assert span is not None
    header_start, body_start, body_end = span
    body = text[body_start:body_end]

    active_re = re.compile(rf'^{re.escape(key)}\s*=.*$', re.MULTILINE)
    commented_re = re.compile(rf'^#\s*{re.escape(key)}\s*=.*$', re.MULTILINE)

    if value is not None:
        new_line = f"{key} = {_toml_str(value)}"
        # Active match wins over a commented sample - otherwise a base shaped
        # like `# zeek_dir = "/default"\nzeek_dir = "/custom"` produces
        # duplicate active keys (the commented line gets uncommented while
        # the existing active line remains, invalidating the TOML).
        active_m = active_re.search(body)
        m = active_m or commented_re.search(body)
        if m is not None:
            # Preserve a trailing inline comment on an existing ACTIVE line; a
            # commented sample being uncommented carries none.
            if active_m is not None:
                comment = _inline_comment(active_m.group())
                if comment:
                    new_line = f"{new_line}  {comment}"
            new_body = body[:m.start()] + new_line + body[m.end():]
        else:
            # Insert directly after the header line. body_start is already
            # past the header newline, so prepending here = post-header.
            new_body = new_line + "\n" + body
        return text[:body_start] + new_body + text[body_end:]

    # value=None: comment the active line (the remove action). A skip disables a
    # source via _disable_sigwood_key, not here.
    if not fresh:
        return text  # never touch a user-set value
    m = re.search(rf'^(?P<key>{re.escape(key)}\s*=.*)$', body, re.MULTILINE)
    if m is None:
        return text  # active line not present; nothing to comment
    line_start = m.start()
    new_body = body[:line_start] + "# " + body[line_start:]
    return text[:body_start] + new_body + text[body_end:]


def _disable_sigwood_key(text: str, key: str) -> str:
    """Rewrite an ACTIVE [sigwood] line for key to explicit-empty so a skipped
    source stays disabled after config fallback.

    A fresh/reset skip of a source that ships an active default line
    (zeek_dir/syslog_dir) writes `key = ""  # disabled during setup`; an explicit
    empty value resolves off, whereas commenting the line would let a shipped
    default re-enable it. A source with no active line (pihole_dir/cloudtrail_dir
    ship commented) is a no-op - it already resolves off.
    """
    span = _sigwood_span(text)
    if span is None:
        return text
    _, body_start, body_end = span
    body = text[body_start:body_end]
    m = re.search(rf'^{re.escape(key)}\s*=.*$', body, re.MULTILINE)
    if m is None:
        return text  # no active line - leave a commented/absent source as-is
    new_line = f'{key} = ""  # disabled during setup'
    new_body = body[:m.start()] + new_line + body[m.end():]
    return text[:body_start] + new_body + text[body_end:]


# ── Prompt-action model ───────────────────────────────────────────────────────
#
# Each source/root prompt resolves to one Action; the writers consume them. The
# end-state of `_resolve_row` MIRRORS `_apply_action` - change them together.

@dataclass(frozen=True)
class Action:
    """A managed-key intent. kind ∈ {set, remove, skip}; value only for set."""

    kind: str
    value: str | None = None


def _set(value: str) -> Action:
    return Action("set", value)


_REMOVE = Action("remove")
_SKIP = Action("skip")


def _normalize_typed(typed: str) -> str:
    """Normalize a typed path to ABSOLUTE: `~` expanded, a relative
    path made absolute against the WIZARD'S CWD (shell semantics) - STORED
    absolute, never reinterpreted under SIGWOOD_ROOT later."""
    return os.path.abspath(os.path.expanduser(typed))


# The universal DROP sentinel for the source/root prompts: `-` removes (configured /
# root) or skips (detected). Matched EXACTLY before _normalize_typed, so a dir
# literally named `-` is reached by typing `./-` (mirrors the HOME MENU's `./a`).
_DROP_SENTINEL = "-"


def _apply_action(text: str, key: str, action: Action, *, fresh: bool) -> str:
    """Apply one Action to the config text via the section-bound upsert.

    THREE non-uniform `fresh` rules - do NOT "simplify" them into one:
      set    → value is not None, so `_upsert` IGNORES `fresh` (writes the
               active line either way).
      remove → ALWAYS fresh=True (comment the active line). A merge remove runs
               under flow fresh=False, but must still COMMENT, not no-op.
      skip   → fresh/reset disables an active default via explicit-empty
               (`_disable_sigwood_key`) so a skipped zeek_dir/syslog_dir stays off
               instead of a shipped default re-enabling it; merge (fresh=False) is a
               strict no-op that preserves a user value.
    """
    if action.kind == "set":
        return _upsert_sigwood_key(text, key, action.value, fresh=fresh)
    if action.kind == "remove":
        return _upsert_sigwood_key(text, key, None, fresh=True)
    # skip
    if not fresh:
        return text
    return _disable_sigwood_key(text, key)


# ── Source prompt specs ───────────────────────────────────────────────────────
#
# label   - friendly name shown in prompts ("Zeek").
# detect  - detection helper (None = opt-in, never detected: CloudTrail).
# globs   - profile globs.
# logs    - logs_label override (None = derive families from globs).
# nudge   - the NOTHING-state copy (no config, no detection). KEEP the voice.

@dataclass(frozen=True)
class _SourceSpec:
    key: str
    label: str
    detect: object  # callable[[], str | None] | None
    globs: tuple[str, ...]
    logs_label: str | None
    nudge: tuple[str, ...]
    recursive: bool = False  # cloudtrail only - native AWSLogs trees are nested
    head_sniff: Callable[[Path], bool] | None = None  # syslog only
    zeek_layout: bool = False  # zeek only - loader-depth flat/dated profile walk


_SOURCE_SPECS: tuple[_SourceSpec, ...] = (
    _SourceSpec(
        "zeek_dir", "Zeek", _detect_zeek, _ZEEK_GLOBS, None,
        (
            "Didn't find Zeek. You might like it: https://zeek.org",
            "If it's just hiding, tell me where.",
        ),
        zeek_layout=True,
    ),
    _SourceSpec(
        "pihole_dir", "Pi-hole", _detect_pihole, (_PIHOLE_GLOB,), "query logs",
        (
            "Pi-hole seems to be absent. Worth a look: https://pi-hole.net",
            "Point me at the logs if they're elsewhere.",
        ),
    ),
    _SourceSpec(
        "cloudtrail_dir", "CloudTrail", None, (_CLOUDTRAIL_GLOB,), "CloudTrail JSON",
        (
            "CloudTrail logs? (opt-in) Point me at a directory of CloudTrail JSON -",
            "e.g. where `sigwood export` lands them under exports/cloudtrail/.",
        ),
        recursive=True,
    ),
)

# System logs is one logical source. Its mode is counted; its file fallback is
# displayed separately and never counted as a second source.
_SOURCE_KEYS: tuple[str, ...] = (
    "zeek_dir", "pihole_dir", "syslog_source", "cloudtrail_dir",
)
_SUMMARY_ORDER: tuple[str, ...] = (
    "zeek_dir", "pihole_dir", "syslog_source", "syslog_dir",
    "cloudtrail_dir", "root",
)
_SUMMARY_LABELS: dict[str, str] = {
    "syslog_source": "system logs",
    "syslog_dir": "file fallback",
}
_SOURCE_LABELS: tuple[tuple[str, str], ...] = tuple(
    (s.key, s.label) for s in _SOURCE_SPECS
)


# ── Wizard dialogue ───────────────────────────────────────────────────────────

def _print_intro(existing_basis: bool) -> None:
    print("OK, let's find your logs.")
    if existing_basis:
        print("Found ~/.sigwood/, using that as basis (non-destructive)")
    print()


def _prompt_source(
    label: str,
    configured: str | None,
    detected: str | None,
    profile: dict | None,
    nudge: tuple[str, ...],
) -> Action:
    """Three-state source prompt → Action. ONE universal grammar (no readline, no
    capability): the value is shown in the headline, Enter KEEPS it verbatim, a
    typed path changes it (normalized), and `-` drops it (remove / skip). Identical
    on every platform."""
    if configured is not None:
        shown = _render_profile(profile) if profile else "nothing there now"
        print(f"Found {label} at {configured} - {shown}.")
        print("[Enter to keep  ·  type a path to change  ·  - to remove]")
        ans = input("> ").strip()
        if ans == "":
            return _set(configured)            # keep verbatim - never normalized
        if ans == _DROP_SENTINEL:
            return _REMOVE
        return _set(_normalize_typed(ans))

    if detected is not None:
        shown = _render_profile(profile) if profile else "nothing there now"
        print(f"Found {label} at {detected} - {shown}. Use it?")
        print("[Enter to use it  ·  type a path  ·  - to skip]")
        ans = input("> ").strip()
        if ans == "":
            return _set(detected)              # keep verbatim - never normalized
        if ans == _DROP_SENTINEL:
            return _SKIP
        return _set(_normalize_typed(ans))

    # nothing - no config, no detection. KEEP the voice.
    for line in nudge:
        print(line)
    print("[Enter to skip  ·  type a path]")
    ans = input("> ").strip()
    if ans == "" or ans == _DROP_SENTINEL:
        return _SKIP
    return _set(_normalize_typed(ans))


_JOURNAL_PROBE_COPY: dict[journal_probe.JournalProbeCode, str] = {
    journal_probe.JournalProbeCode.READY: "available",
    journal_probe.JournalProbeCode.EMPTY: "reachable, no entries returned",
    journal_probe.JournalProbeCode.EXECUTABLE_MISSING: (
        "unavailable, journalctl not found"
    ),
    journal_probe.JournalProbeCode.SPAWN_FAILED: (
        "unavailable, journalctl could not start"
    ),
    journal_probe.JournalProbeCode.EXIT_NONZERO: (
        "unavailable, journal query failed"
    ),
    journal_probe.JournalProbeCode.SIGNALLED: (
        "unavailable, journal query was interrupted"
    ),
    journal_probe.JournalProbeCode.INVALID_UTF8: (
        "unavailable, journal returned invalid UTF-8"
    ),
    journal_probe.JournalProbeCode.RECORD_TOO_LARGE: (
        "unavailable, journal entry exceeded the probe limit"
    ),
}


def _journal_probe_copy(result: journal_probe.JournalProbeResult) -> str:
    """Render only the tool-owned reason code, never child output."""
    return _JOURNAL_PROBE_COPY[result.code]


@dataclass(frozen=True)
class _SystemLogsState:
    """One compound system-log prompt's starting state and Enter actions."""

    mode: syslog_mode.SyslogMode
    migrated: bool
    existing_config: bool
    dir_present: bool
    dir_value: str | None
    detected: str | None
    fallback_display: str | None
    fallback_defaulted: bool
    profile: dict | None
    enter_mode: Action
    enter_dir: Action


def _preserve_syslog_dir(*, present: bool, value: str | None) -> Action:
    """Preserve a raw fallback value, including explicit empty or absence."""
    if present:
        return _set(value or "")
    # Against an absent merge key this is a no-op. Against the active reset
    # template it comments the default, preserving raw absence in both flows.
    return _REMOVE


def _system_logs_state(
    existing: dict,
    *,
    fresh_install: bool,
    probe: journal_probe.JournalProbeResult,
    root: str,
) -> _SystemLogsState:
    """Build a compound default without letting live probes rewrite config intent."""
    if fresh_install:
        detected = _detect_syslog()
        if probe.code is journal_probe.JournalProbeCode.READY:
            mode = syslog_mode.SyslogMode.AUTO
            dir_action = _set(detected or "")
        elif detected is not None:
            mode = syslog_mode.SyslogMode.FILES
            dir_action = _set(detected)
        else:
            mode = syslog_mode.SyslogMode.OFF
            dir_action = _set("")
        fallback = detected
        profile = None
        if fallback is not None:
            profile = _profile_dir(
                resolve_path(fallback, root),
                (_SYSLOG_GLOB,),
                logs_label=None,
                head_sniff=_looks_like_syslog_head,
            )
        return _SystemLogsState(
            mode=mode,
            migrated=False,
            existing_config=False,
            dir_present=False,
            dir_value=None,
            detected=detected,
            fallback_display=fallback,
            fallback_defaulted=False,
            profile=profile,
            enter_mode=_set(mode.value),
            enter_dir=dir_action,
        )

    mode_present = "syslog_source" in existing
    dir_present = "syslog_dir" in existing
    raw_dir = existing.get("syslog_dir")
    if dir_present and not isinstance(raw_dir, str):
        raise ValueError(
            f"syslog_dir must be a path string (got {raw_dir!r})"
        )
    classified = syslog_mode.classify_configured_syslog_mode(
        mode_present=mode_present,
        mode_value=existing.get("syslog_source"),
        dir_present=dir_present,
        dir_value=raw_dir,
        disk_shape=True,
    )
    fallback = raw_dir if dir_present and raw_dir else (
        None if dir_present else _DEFAULT_SYSLOG_DIR
    )
    profile = None
    if fallback is not None and dir_present:
        profile = _profile_dir(
            resolve_path(fallback, root),
            (_SYSLOG_GLOB,),
            logs_label=None,
            head_sniff=_looks_like_syslog_head,
        )
    return _SystemLogsState(
        mode=classified.mode,
        migrated=classified.legacy_migrated,
        existing_config=True,
        dir_present=dir_present,
        dir_value=raw_dir,
        detected=None,
        fallback_display=fallback,
        fallback_defaulted=not dir_present,
        profile=profile,
        enter_mode=_set(classified.mode.value),
        enter_dir=_preserve_syslog_dir(present=dir_present, value=raw_dir),
    )


def _prompt_system_log_path() -> tuple[Action, Action]:
    """Require a file fallback after an explicit files selection."""
    while True:
        print("files needs a non-empty system-log directory")
        print("[type a path  ·  - to turn system logs off]")
        ans = input("> ").strip()
        if ans == _DROP_SENTINEL or ans.lower() == "off":
            return (_set(syslog_mode.SyslogMode.OFF.value), _set(""))
        if ans:
            return (
                _set(syslog_mode.SyslogMode.FILES.value),
                _set(_normalize_typed(ans)),
            )


def _prompt_system_logs(
    state: _SystemLogsState,
    probe: journal_probe.JournalProbeResult,
) -> tuple[Action, Action]:
    """Prompt once for the compound mode plus its optional file fallback."""
    migrated = " (migrated from legacy config)" if state.migrated else ""
    if state.fallback_display is None:
        fallback = "(none)"
    else:
        fallback = state.fallback_display
        if state.fallback_defaulted:
            fallback += " (default; key not set)"
    if state.profile is not None:
        fallback += f" - {_render_profile(state.profile)}"

    print(f"System logs: {state.mode.value}{migrated}")
    print(f"  journal: {_journal_probe_copy(probe)}")
    print(f"  file fallback: {fallback}")
    print("[Enter] use this setting   [a] auto   [j] journal   [f] files")
    print("[type a path for files  ·  - to turn system logs off]")
    ans = input("> ").strip()
    low = ans.lower()

    if ans == "":
        return (state.enter_mode, state.enter_dir)
    if ans == _DROP_SENTINEL or low == "off":
        return (_set(syslog_mode.SyslogMode.OFF.value), _set(""))
    if low in ("j", "journal"):
        dir_action = (
            _preserve_syslog_dir(
                present=state.dir_present, value=state.dir_value,
            )
            if state.existing_config
            else _set("")
        )
        return (_set(syslog_mode.SyslogMode.JOURNAL.value), dir_action)
    if low in ("a", "auto"):
        if state.existing_config and state.dir_present:
            dir_action = _set(state.dir_value or "")
        elif not state.existing_config and state.detected is not None:
            dir_action = _set(state.detected)
        else:
            dir_action = _set("")
        return (_set(syslog_mode.SyslogMode.AUTO.value), dir_action)
    if low in ("f", "files"):
        if state.existing_config and state.dir_present and state.dir_value:
            return (
                _set(syslog_mode.SyslogMode.FILES.value),
                _set(state.dir_value),
            )
        if state.existing_config and not state.dir_present:
            return (
                _set(syslog_mode.SyslogMode.FILES.value),
                _REMOVE,
            )
        if state.detected is not None:
            return (
                _set(syslog_mode.SyslogMode.FILES.value),
                _set(state.detected),
            )
        return _prompt_system_log_path()

    return (
        _set(syslog_mode.SyslogMode.FILES.value),
        _set(_normalize_typed(ans)),
    )


def _disp_root(value: str) -> str:
    """Render a root VALUE for a prompt/confirm line (an explicit "" = CWD)."""
    return "(current directory)" if value == "" else value


def _home_menu(lead: str) -> str:
    """Shared home/root menu: ONE option parser/renderer, a CONTEXT-SPECIFIC
    `lead`. Returns the chosen TOKEN - Enter/'a' → ~/.sigwood, 'b' →
    /etc/sigwood (LITERAL preset tokens, expanded at resolve time), else a typed
    path normalized absolute. Exact-match a/b case-insensitive; a dir literally
    named a/b must be typed ./a. We do NOT profile/validate the presets."""
    print(lead)
    print("[a] ~/.sigwood    (default)")
    print("[b] /etc/sigwood  (system-wide)")
    print("· or type a path  (for a dir named 'a'/'b', type ./a)")
    ans = input("> ").strip()
    low = ans.lower()
    if ans == "" or low == "a":
        return _DEFAULT_ROOT
    if low == "b":
        return _SYSTEM_ROOT
    return _normalize_typed(ans)


def _prompt_root(*, present: bool, default: str | None) -> Action:
    """Root prompt → Action. State keys on PRESENCE, not truthiness. TWO cases:

    unset   → the shared HOME MENU sets the data root.
    present → ANY value (incl. "") keeps on Enter (verbatim - "" stays the current
        directory, a ~/relative root is not normalized), a typed path changes it,
        and `-` removes it (reverts to the default). Without prefill, `-` is
        unambiguous, so root="" needs no special branch.
    """
    if not present:
        return _set(_home_menu(_UNSET_ROOT_LEAD))

    assert default is not None
    print(f"root is set to {_disp_root(default)} - keep it?")
    print("[Enter to keep  ·  type a path to change  ·  - to remove]")
    ans = input("> ").strip()
    if ans == "":
        return _set(default)               # keep verbatim - never normalized
    if ans == _DROP_SENTINEL:
        return _REMOVE
    return _set(_normalize_typed(ans))


def _print_merge_reset(config_path: Path) -> None:
    print(f"Found a config: {config_path}")
    print("[m] merge   [r] reset")


def _print_reset_scope() -> None:
    print("Reset what?  [c] config   [a] allowlist   [b] both")


# ── Change summary + accept / redo / abort ────────────────────────────────────

def _resolve_row(
    key: str, action: Action, existing_value: str | None, *, present: bool,
    flow: str,
) -> tuple[str | None, str]:
    """Resolve one managed key to (resulting_value, annotation). The SINGLE
    owner of value+verb derivation - renderer, advisory, and confirm all read
    this so they cannot drift. Mirrors `_apply_action`'s end-state."""
    if key == "root":
        if action.kind == "set":
            v = action.value
            if not present:
                return (v, "added")
            return (v, "unchanged") if existing_value == v else (v, f"was: {existing_value}")
        if action.kind == "remove":
            return (None, "removed (reverts to default)")
        # Defensive: root is now always set/removed (unset routes through the HOME
        # MENU, which yields a `set`), so a root `skip` is unreachable. Kept so the
        # mirror handles every kind; reverts to the effective default if it fires.
        return (_DEFAULT_ROOT, "preserved")

    # sources
    if action.kind == "set":
        v = action.value
        if existing_value is None:
            return (v, "added")
        return (v, "unchanged") if existing_value == v else (v, f"was: {existing_value}")
    if action.kind == "remove":
        return (None, "removed" if existing_value is not None else "(not set)")
    # skip
    if flow == "merge":
        return (existing_value, "unchanged") if existing_value is not None else (None, "(not set)")
    # fresh/reset skip leaves the source off (active default -> explicit empty, or a
    # commented source absent); the summary names it plainly.
    return (None, "skipped")


def _resolve_all(
    actions: dict[str, Action], existing: dict, *, flow: str,
) -> dict[str, tuple[str | None, str]]:
    """Resolve every managed key once, preserving compound fallback provenance."""
    out: dict[str, tuple[str | None, str]] = {}
    for key in _MANAGED_KEYS:
        if key in ("syslog_source", "syslog_dir"):
            continue
        present = key in existing
        ev = existing.get(key)
        if key != "root":
            ev = ev or None
        out[key] = _resolve_row(key, actions[key], ev, present=present, flow=flow)

    mode_present = "syslog_source" in existing
    out["syslog_source"] = _resolve_row(
        "syslog_source",
        actions["syslog_source"],
        existing.get("syslog_source") if mode_present else None,
        present=mode_present,
        flow=flow,
    )

    dir_present = "syslog_dir" in existing
    raw_dir, dir_ann = _resolve_row(
        "syslog_dir",
        actions["syslog_dir"],
        existing.get("syslog_dir") if dir_present else None,
        present=dir_present,
        flow=flow,
    )
    if actions["syslog_dir"].kind == "remove":
        raw_dir = _DEFAULT_SYSLOG_DIR
        dir_ann = (
            "removed (reverts to default)"
            if dir_present
            else "preserved (default; key not set)"
        )
    out["syslog_dir"] = (raw_dir, dir_ann)
    return out


def _disp_value(key: str, value: str | None) -> str:
    """Render root-empty and fallback-empty without conflating their meanings."""
    if value is None:
        return "-"
    if value == "":
        return _disp_root(value) if key == "root" else "(none)"
    return value


def _source_active(
    key: str, resolved: dict[str, tuple[str | None, str]],
) -> bool:
    """Return whether one logical source lane is enabled."""
    value = resolved[key][0]
    if key == "syslog_source":
        return value != syslog_mode.SyslogMode.OFF.value
    return value is not None


def _render_summary(
    config_path: Path,
    resolved: dict[str, tuple[str | None, str]],
    probe: journal_probe.JournalProbeResult,
) -> None:
    """Print the change summary (aligned) BEFORE any write. The VALUE column is
    the resulting config value; the ANNOTATION is the change verb."""
    print(f"About to write {config_path}:")
    labels = {
        key: _SUMMARY_LABELS.get(key, key) for key in _SUMMARY_ORDER
    }
    keyw = max(
        [len(label) for label in labels.values()] + [len("journal probe")]
    )
    valw = max(
        len(_disp_value(key, resolved[key][0])) for key in _SUMMARY_ORDER
    )
    for key in _SUMMARY_ORDER:
        value, ann = resolved[key]
        shown = _disp_value(key, value)
        print(f"  {labels[key].ljust(keyw)}  {shown.ljust(valw)}  {ann}")
    print(f"  {'journal probe'.ljust(keyw)}  {_journal_probe_copy(probe)}")
    if not any(_source_active(k, resolved) for k in _SOURCE_KEYS):
        print()
        print("No sources set - sigwood will need files on the command line.")
    print()


def _confirm_accept() -> str:
    """Render the accept gate and return one of accept / redo / abort. Loops on
    an unrecognized token (no accidental write or abort on a typo)."""
    while True:
        print("[Enter] accept  ·  [r] redo  ·  [a] abort")
        ans = input("> ").strip().lower()
        if ans == "":
            return "accept"
        if ans in ("r", "redo"):
            return "redo"
        if ans in ("a", "abort"):
            return "abort"


def _print_confirm(
    config_path: Path,
    resolved: dict[str, tuple[str | None, str]],
    probe: journal_probe.JournalProbeResult,
) -> None:
    labels = dict(_SOURCE_LABELS)
    active: list[tuple[str, str]] = []
    for key in ("zeek_dir", "pihole_dir"):
        value = resolved[key][0]
        if value is not None:
            active.append((labels[key], value))
    mode = resolved["syslog_source"][0]
    if mode != syslog_mode.SyslogMode.OFF.value:
        active.append(("system logs", mode or syslog_mode.SyslogMode.AUTO.value))
    cloudtrail = resolved["cloudtrail_dir"][0]
    if cloudtrail is not None:
        active.append((labels["cloudtrail_dir"], cloudtrail))
    if active:
        sources_line = ", ".join(f"{label} ({path})" for label, path in active)
    else:
        sources_line = "(none - pass files on the command line)"
    root_val = resolved["root"][0]
    data_line = _disp_root(root_val) if root_val is not None else _DEFAULT_ROOT
    print(f"Done - settings written to {config_path}.")
    print(f"  reading:  {sources_line}")
    print(f"  file fallback: {_disp_value('syslog_dir', resolved['syslog_dir'][0])}")
    print(f"  journal probe: {_journal_probe_copy(probe)}")
    print(f"  data:     {data_line}")
    print()
    print(f"sigwood documentation lives here: {_DOCS_URL}")
    print("Or just run `sigwood` for a quick-start TL;DR. Good hunting!")


# ── Source / root collection ──────────────────────────────────────────────────

def _effective_root_with_default(section: dict) -> str:
    """effective_root mirroring cfg.load's deep-merge: a ROOTLESS config runs
    under _DEFAULT_ROOT, so inject it when 'root' is ABSENT (env SIGWOOD_ROOT
    still wins; an explicit root="" stays CWD). The single init-time owner of
    root resolution for previewing/resolving config-relative values."""
    if os.environ.get("SIGWOOD_ROOT") is None and "root" not in section:
        section = {**section, "root": _DEFAULT_ROOT}
    return effective_root({"sigwood": section})


def _collect_source_action(
    spec: _SourceSpec, existing: dict, *, root: str,
) -> Action:
    """Collect one ordinary directory-source action."""
    configured = existing.get(spec.key) or None
    detected: str | None = None
    if configured is None and spec.detect is not None:
        detected = spec.detect()  # type: ignore[operator]
    default = configured or detected
    profile = None
    if default is not None:
        resolved_default = resolve_path(default, root)
        profile = _profile_dir(
            resolved_default, spec.globs,
            logs_label=spec.logs_label, recursive=spec.recursive,
            head_sniff=spec.head_sniff, zeek_layout=spec.zeek_layout,
        )
    return _prompt_source(
        spec.label, configured, detected, profile, spec.nudge,
    )


def _collect_actions(
    existing: dict, *, fresh_install: bool,
) -> tuple[dict[str, Action], journal_probe.JournalProbeResult]:
    """Collect three directory sources plus one compound system-log lane."""
    actions: dict[str, Action] = {}
    root = _effective_root_with_default(existing)
    for spec in _SOURCE_SPECS[:2]:
        actions[spec.key] = _collect_source_action(spec, existing, root=root)
        print()

    probe = journal_probe.probe_journal()
    state = _system_logs_state(
        existing, fresh_install=fresh_install, probe=probe, root=root,
    )
    mode_action, dir_action = _prompt_system_logs(state, probe)
    actions["syslog_source"] = mode_action
    actions["syslog_dir"] = dir_action
    print()

    for spec in _SOURCE_SPECS[2:]:
        actions[spec.key] = _collect_source_action(spec, existing, root=root)
        print()
    return actions, probe


# ── Home discovery, pre-flight, allowlist.d seeding ───────────────────────────

def _expanded_homes() -> list[Path]:
    """The known sigwood homes, expanded at CALL time (HOME-aware)."""
    return [Path(h).expanduser() for h in _SEARCH_HOMES]


def _find_initial_config() -> Path | None:
    """First existing <home>/config.toml over the search homes (user wins).

    The call-time mirror of cfg._find_config_file() - the source of truth for the
    initial merge/reset-vs-fresh branch."""
    for home in _expanded_homes():
        config = home / "config.toml"
        if config.exists():
            return config
    return None


def _is_search_home(home: Path) -> bool:
    """True when home is one of the auto-discovered search homes."""
    return any(home == h for h in _expanded_homes())


def _resolve_allowlist_dir_from_config(config_path: Path) -> Path:
    """Resolve [allowlist].allowlist_dir from a config file through the SINGLE
    path-resolution owner (common/paths) - default "allowlist.d/", SIGWOOD_ROOT-
    relative (env SIGWOOD_ROOT honored via effective_root), absolute and ~
    respected. This is cli_init's one allowlist-dir resolver: seeding (fresh),
    reset-config-both, and reset-allowlist all route the just-written / existing
    config through it, so the operator's CONFIGURED directory is always honored.
    Falls back to the default under the config's home on an unreadable/absent
    key (never raises)."""
    try:
        parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        parsed = {}
    section = parsed.get("sigwood", {})
    # A ROOTLESS config resolves allowlist.d/ under the default ~/.sigwood (where
    # cfg.load puts it), NOT the CWD - via the shared root-default owner, which
    # preserves an explicit root = "" as CWD and lets env SIGWOOD_ROOT win.
    allowlist_dir = parsed.get("allowlist", {}).get("allowlist_dir") or "allowlist.d/"
    resolved = resolve_path(allowlist_dir, _effective_root_with_default(section))
    return Path(resolved) if resolved else config_path.parent / "allowlist.d"


def _shadow_refusal(home: Path) -> str | None:
    """REFUSE writing a config cfg.load() would never read: a /etc/sigwood
    install while a higher-priority ~/.sigwood/config.toml exists. Touches no
    user files - returns the actionable message or None."""
    user_home_config = Path(_SEARCH_HOMES[0]).expanduser() / "config.toml"
    if home == Path(_SEARCH_HOMES[1]).expanduser() and user_home_config.exists():
        return (
            "a ~/.sigwood/config.toml would shadow "
            "/etc/sigwood on every run - remove or rename it first, or install "
            "to ~/.sigwood"
        )
    return None


def _writability_error(home: Path, *, private: bool = True) -> str | None:
    """Probe that init can create <home> and write inside it. Returns an
    actionable message or None. Creates <home> on success (mkdir is the probe).

    Used by the RESET arms only - they operate on an ALREADY-EXISTING home, so
    the mkdir is a no-op and there is no new-dir lie. The FRESH location flow
    uses the NON-MUTATING `_writable_ancestor` instead (see `_preflight`)."""
    try:
        private_mkdir(home, private=private)
        probe = home / ".sigwood_init_write_probe"
        with private_open(probe, private=private, encoding="utf-8"):
            pass
        probe.unlink()
        return None
    except OSError as exc:
        return (
            f"can't write to {home} ({exc}) - "
            "re-run with sudo, or pick another location"
        )


def _writable_ancestor(home: Path) -> str | None:
    """NON-MUTATING writability probe for the FRESH location: walk to the
    nearest EXISTING ancestor and check ``os.access(W_OK)``. Creates NOTHING -
    the actual home mkdir happens post-accept in `_write_config`, so an abort or
    redo leaves no partial home. Catches the common no-perm case (e.g.
    /etc/sigwood as non-root → ancestor /etc not writable → graceful
    re-prompt)."""
    anc = home
    while not anc.exists():
        parent = anc.parent
        if parent == anc:
            break
        anc = parent
    if not os.access(anc, os.W_OK):
        return f"can't write to {home} - re-run with sudo, or pick another location"
    return None


def _preflight(home: Path) -> str | None:
    """FRESH location preflight. Shadow check FIRST (pure - no fs writes, so a
    refusal leaves no partial home), then the NON-MUTATING writability probe (no
    mkdir before the user accepts the summary). Returns the first failure or
    None."""
    reason = _shadow_refusal(home)
    if reason is not None:
        return reason
    return _writable_ancestor(home)


def _load_allowlist_template(name: str) -> str:
    """Return a shipped allowlist template (package resources)."""
    try:
        import importlib.resources
        pkg = importlib.resources.files("sigwood") / "data" / "allowlist"
        return (pkg / name).read_text(encoding="utf-8")
    except Exception:
        path = Path(__file__).parent / "data" / "allowlist" / name
        return path.read_text(encoding="utf-8")


def _seed_allowlist_d(allowlist_d: Path, *, private: bool = True) -> None:
    """Copy the flat drop-in templates into allowlist.d IF ABSENT. Idempotent;
    never overwrites an existing user file. Curated lists are not copied."""
    private_mkdir(allowlist_d, private=private)
    for name in _ALLOWLIST_SEED_FILES:
        dst = allowlist_d / name
        if not dst.exists():
            private_write_text(
                dst, _load_allowlist_template(name),
                private=private, encoding="utf-8",
            )


def _reset_allowlist_d(allowlist_d: Path, *, private: bool = True) -> None:
    """Delete ONLY the dot-free prefixed drop-ins (domains* / connections*) that
    classify as a suppression list, then re-seed blanks. PRESERVES *.toml stanzas,
    any DOTTED name (including a legacy connections.txt), hidden and ~-terminated
    names, subdirectories, and dot-free UNPREFIXED names (e.g. notes). A dot-free
    prefixed file IS claimed by the reserved namespace and is deleted. Curated
    package lists live in the package, never here, so they are untouched."""
    if allowlist_d.is_dir():
        for f in sorted(allowlist_d.iterdir()):
            if f.is_file() and _classify_dropin(f.name) in ("domain", "numeric"):
                f.unlink()
    _seed_allowlist_d(allowlist_d, private=private)


def _read_existing_config_for_root(
    target: Path,
) -> tuple[bytes | None, str | None, dict | None]:
    """Read an existing config file. Returns (raw_bytes, decoded_text,
    parsed-sigwood-dict). Bytes are preserved verbatim for `.bak`
    (read_text translates CRLF→LF under universal newlines, which would
    break the non-clobber guarantee for Windows-line-ending files)."""
    if not target.exists():
        return (None, None, None)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise ValueError(
            f"cannot read existing config at {target}: {exc}"
        ) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"existing config at {target} is not UTF-8: {exc}"
        ) from exc
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(
            f"existing config at {target} is not valid TOML: {exc}"
        ) from exc
    return (raw, text, parsed.get("sigwood", {}))


def _validate_existing_syslog_source(existing: dict) -> None:
    """Fail on an explicit invalid mode before probing or source prompts."""
    if "syslog_source" in existing:
        syslog_mode.parse_syslog_mode(existing["syslog_source"])


def _load_example_text() -> str:
    """Return the shipped config_example.toml contents."""
    try:
        import importlib.resources
        pkg_data = importlib.resources.files("sigwood") / "data"
        return (pkg_data / "config_example.toml").read_text(encoding="utf-8")
    except Exception:
        example_path = Path(__file__).parent / "data" / "config_example.toml"
        return example_path.read_text(encoding="utf-8")


class _Redirect:
    """Custom-home re-detect signal: the chosen home holds its own config, so
    the in-flight (pre-location) source answers are DISCARDED and the merge/reset
    decision is re-entered for the discovered config."""

    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path


# ── Config writing (post-accept commit) ───────────────────────────────────────

def _write_config(
    target: Path, text_base: str, actions: dict[str, Action], *,
    fresh: bool, existing_raw: bytes | None, private: bool = True,
) -> None:
    """POST-ACCEPT commit: create the home, `.bak` the existing file (verbatim
    bytes), apply every managed Action over ``text_base``, write. The ONLY
    mutating step for fresh/reset-config - never reached on abort/redo.

    A home-mkdir failure surfaces the actionable ValueError at the CLI boundary
    (the E1 backstop for the non-mutating fresh preflight)."""
    try:
        private_mkdir(target.parent, private=private)
    except OSError as exc:
        raise ValueError(
            f"can't write to {target.parent} ({exc}) - "
            "re-run with sudo, or pick another location"
        ) from exc
    if existing_raw is not None:
        bak_path = target.with_suffix(".toml.bak")
        try:
            private_write_bytes(bak_path, existing_raw, private=private)
        except OSError as exc:
            raise ValueError(
                f"cannot write backup at {bak_path}: {exc}"
            ) from exc

    text = text_base
    for key in _MANAGED_KEYS:
        text = _apply_action(text, key, actions[key], fresh=fresh)
    try:
        private_write_bytes(target, text.encode("utf-8"), private=private)
    except OSError as exc:
        raise ValueError(
            f"can't write {target} ({exc}) - "
            "re-run with sudo, or pick another location"
        ) from exc


# ── Flows ─────────────────────────────────────────────────────────────────────

def _location_flow() -> tuple[Path, str] | _Redirect:
    """Prompt for the sigwood home via the shared HOME MENU (the location answer
    IS the root - fresh asks once). Loops on a shadow refusal / writability failure
    (re-prompt). Returns (home, root_value token), or a _Redirect when a custom
    home already holds its own config.

    NON-MUTATING - `_preflight` does not create the home; the home is
    created post-accept in `_write_config`."""
    while True:
        root_value = _home_menu(_FRESH_LOCATION_LEAD)
        print()
        home = Path(root_value).expanduser()

        # Custom-home re-detect - BEFORE any write. Discards the pre-location
        # source answers (caller drops them) and re-enters merge/reset.
        if not _is_search_home(home) and (home / "config.toml").exists():
            return _Redirect(home / "config.toml")

        reason = _preflight(home)
        if reason is not None:
            print(reason)
            print()
            continue  # re-prompt the location

        if not _is_search_home(home):
            print(
                f"Note: {home}/config.toml is not auto-discovered - run sigwood "
                f"with --config={home}/config.toml."
            )
            print()
        return (home, root_value)


def _do_merge(
    config_path: Path, existing_bytes: bytes, existing_text: str, existing_section: dict,
    *, private: bool = True,
) -> None:
    """Non-destructive merge over the existing config text (fresh=False - skips
    preserve user values; tuning and exporter stanzas survive byte-identical).
    merge now also MANAGES root (presence-based). Summary + accept/redo/abort
    gate every write."""
    _validate_existing_syslog_source(existing_section)
    while True:
        actions, probe = _collect_actions(
            existing_section, fresh_install=False,
        )
        actions["root"] = _prompt_root(
            present="root" in existing_section, default=existing_section.get("root"),
        )
        print()
        resolved = _resolve_all(actions, existing_section, flow="merge")
        _render_summary(config_path, resolved, probe)
        decision = _confirm_accept()
        if decision == "abort":
            print("Aborted - nothing changed.")
            return
        if decision == "redo":
            print()
            continue
        break

    _write_config(
        config_path, existing_text, actions, fresh=False, existing_raw=existing_bytes,
        private=private,
    )
    print()
    _print_confirm(config_path, resolved, probe)


def _entry_for_config(config_path: Path) -> None:
    """Merge / reset decision for an existing config. Reached for a discovered
    search-home config AND (via _Redirect) a typed custom-home config."""
    private = config_path.parent != Path(_SYSTEM_ROOT)
    existing_bytes, existing_text, existing_section = _read_existing_config_for_root(config_path)
    assert existing_bytes is not None and existing_text is not None

    _print_merge_reset(config_path)
    while True:
        choice = input("> ").strip().lower()
        if choice in ("", "m", "merge"):
            print()
            _do_merge(
                config_path, existing_bytes, existing_text,
                existing_section or {}, private=private,
            )
            return
        if choice in ("r", "reset"):
            print()
            break
    _do_reset(config_path, existing_section or {}, private=private)


def _do_reset(
    config_path: Path, existing_section: dict, *, private: bool = True,
) -> None:
    """Reset config / allowlist / both for an existing install, behind a TYPED
    `reset` confirmation. An unrecognized scope ABORTS (no `both` default - that
    would silently widen a fat-finger into the broadest destructive reset)."""
    _print_reset_scope()
    scope_in = input("> ").strip().lower()
    if scope_in in ("c", "config"):
        scope = "config"
    elif scope_in in ("a", "allowlist"):
        scope = "allowlist"
    elif scope_in in ("b", "both"):
        scope = "both"
    else:
        print("Unrecognized choice - nothing changed.")
        return
    print()

    print('This regenerates files. Type "reset" to confirm (anything else aborts).')
    if input("> ").strip() != "reset":
        print("Aborted - nothing changed.")
        return
    print()

    if scope in ("config", "both"):
        # Reset-config regenerates IN PLACE at the discovered config - NO location
        # prompt. Location is a FRESH-INSTALL concept; an existing config already
        # HAS a home. The existing root is PRESERVED via the presence-based root
        # prompt (default = existing root); an unset root routes through the HOME
        # MENU, whose Enter writes the explicit default ~/.sigwood. Pre-flight
        # writability of the config home FIRST (friendly message, existing home →
        # mutating probe is a no-op), BEFORE any question.
        _validate_existing_syslog_source(existing_section)
        reason = _writability_error(config_path.parent, private=private)
        if reason is not None:
            print(reason)
            return

        while True:
            actions, probe = _collect_actions(
                existing_section, fresh_install=False,
            )
            actions["root"] = _prompt_root(
                present="root" in existing_section, default=existing_section.get("root"),
            )
            print()
            resolved = _resolve_all(actions, existing_section, flow="reset")
            _render_summary(config_path, resolved, probe)
            decision = _confirm_accept()
            if decision == "abort":
                print("Aborted - nothing changed.")
                return
            if decision == "redo":
                print()
                continue
            break

        existing_raw = config_path.read_bytes() if config_path.exists() else None
        _write_config(
            config_path, _load_example_text(), actions, fresh=True,
            existing_raw=existing_raw, private=private,
        )
        if scope == "both":
            _reset_allowlist_d(
                _resolve_allowlist_dir_from_config(config_path), private=private,
            )
        print()
        _print_confirm(config_path, resolved, probe)
        return

    # scope == "allowlist": honor the existing config's [allowlist].allowlist_dir
    # (default "allowlist.d/", SIGWOOD_ROOT-relative, abs/~ respected) - NOT a hardcoded
    # home/allowlist.d. Preflight the ACTUAL target before deleting/seeding.
    allowlist_d = _resolve_allowlist_dir_from_config(config_path)
    reason = _writability_error(allowlist_d, private=private)
    if reason is not None:
        print(reason)
        return
    _reset_allowlist_d(allowlist_d, private=private)
    print(f"Reset allowlist drop-ins under {allowlist_d} (curated lists untouched).")


def _fresh_flow() -> None:
    """No config found anywhere - gather sources, choose a home (which IS the root
    - asked once), summarize, and only on accept write fresh + seed allowlist.d."""
    _print_intro(False)
    while True:
        actions, probe = _collect_actions({}, fresh_install=True)
        loc = _location_flow()
        if isinstance(loc, _Redirect):
            # The typed custom home already holds a config - discard sources,
            # hand off to merge/reset (which owns its OWN summary/accept). The
            # redirect is terminal: never a redo candidate.
            _entry_for_config(loc.config_path)
            return
        home, root_value = loc
        private = home != Path(_SYSTEM_ROOT)
        # The location answer IS the root - no separate root prompt.
        actions["root"] = _set(root_value)
        config_path = home / "config.toml"
        resolved = _resolve_all(actions, {}, flow="fresh")
        _render_summary(config_path, resolved, probe)
        decision = _confirm_accept()
        if decision == "abort":
            print("Aborted - nothing changed.")
            return
        if decision == "redo":
            print()
            continue
        break

    existing_raw = config_path.read_bytes() if config_path.exists() else None
    _write_config(
        config_path, _load_example_text(), actions, fresh=True,
        existing_raw=existing_raw, private=private,
    )
    _seed_allowlist_d(
        _resolve_allowlist_dir_from_config(config_path), private=private,
    )
    print()
    _print_confirm(config_path, resolved, probe)


def run_init() -> None:
    """Detection-driven, non-clobbering wizard for the first-run config.

    Public entry point - ``cli.py`` validates argv via ``_parse_args(args,
    "init")`` (allowed set is help-only; standalone ``--help``/``-h`` is
    short-circuited before this function is invoked) and then delegates here.

    Discovery: the first existing <home>/config.toml over the search homes routes
    to merge/reset; none found routes to the fresh flow (sources → location →
    root → summary → accept → write + allowlist.d seeding).

    End-of-input (Ctrl-D / closed stdin) at ANY prompt aborts like the explicit
    abort choices: no filesystem mutation happens before the summary accept and
    no prompt exists after it, so "nothing changed" is truthful everywhere.
    """
    initial = _find_initial_config()
    try:
        if initial is not None:
            _entry_for_config(initial)
        else:
            _fresh_flow()
    except EOFError:
        # Ctrl-D does not echo a newline, so on a TTY the abort line would land
        # on the "> " prompt row; non-TTY output stays byte-clean.
        if sys.stdout.isatty():
            print()
        print("Aborted - nothing changed.")


# Compat shim - pre-extraction tests called `cli._run_init([])`. The new entry
# is ``run_init()`` (cli.py validates argv via ``_parse_args(args, "init")``
# before delegating). Tests that drive the wizard end-to-end keep working.
def _run_init(args: list[str] | None = None) -> None:
    """Wrapper that preserves the pre-extraction call shape for tests."""
    del args
    run_init()
