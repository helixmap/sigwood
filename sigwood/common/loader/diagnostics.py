"""Loader warning/wording + log-type helpers (leaf utility module).

The non-dataclass glue kept out of ``types``: ``_log_type`` (glob →
canonical log type), ``_schema_warning`` (actionable missing-field message),
``_zeek_file_read_warning`` / ``_cloudtrail_parse_warning`` /
``_zeek_file_parse_warning`` / ``_zeek_bad_lines_warning`` (privacy-safe
per-file failure wording). Imports the parser schema constants and the
``plural`` display helper only.
"""

from __future__ import annotations

import gzip
import lzma
import os
import stat
from pathlib import Path

try:
    import grp
    import pwd
except ImportError:  # non-POSIX platforms (e.g. Windows) ship neither module
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

import pandas as pd

from sigwood.common.display import plural
from sigwood.parsers.zeek import (
    _OPTIONAL_COLUMNS,
    _REQUIRED_COLUMNS,
)

# Exact usermod advice is restricted to dedicated least-privilege log-reader
# groups; joining an arbitrary owning group can confer elevated authority.
_LOG_READER_GROUPS: frozenset[str] = frozenset({"adm"})


def _log_type(pattern: str) -> str | None:
    """Return the canonical log type inferred from a loader glob pattern."""
    if pattern.startswith("conn"):
        return "conn"
    if pattern.startswith("dns"):
        return "dns"
    if pattern.startswith("ssl"):
        return "ssl"
    if pattern.startswith("weird"):
        return "weird"
    if pattern.startswith("notice"):
        return "notice"
    if pattern.startswith("auth"):
        return "auth"
    if pattern.startswith("files"):
        return "files"
    if pattern.startswith("pihole"):
        return "pihole"
    if pattern.startswith("syslog"):
        return "syslog"
    return None


def _schema_warning(pattern: str, df: pd.DataFrame) -> str | None:
    """Return an actionable warning when a loaded DataFrame lacks canonical fields."""
    if df.empty:
        return None

    log_type = _log_type(pattern)
    if log_type is None or log_type not in _REQUIRED_COLUMNS:
        return None

    opt = _OPTIONAL_COLUMNS.get(log_type, set())
    missing = sorted((_REQUIRED_COLUMNS[log_type] - opt) - set(df.columns))
    if not missing:
        return None

    if log_type == "conn":
        return (
            f"conn.log fields not found: {', '.join(missing)} - "
            "is this a Zeek conn.log?"
        )
    if log_type == "dns":
        return (
            f"dns.log fields not found: {', '.join(missing)} - "
            "is this a Zeek dns.log?"
        )
    if log_type == "syslog":
        return (
            f"syslog.log fields not found: {', '.join(missing)} - "
            "is this a Zeek syslog.log?"
        )
    return None


def _zeek_file_read_warning(
    path: Path,
    exc: BaseException,
    *,
    display_label: str | None = None,
) -> str:
    """Return a privacy-safe warning for a Zeek file that could not be read."""
    if isinstance(exc, (EOFError, gzip.BadGzipFile, lzma.LZMAError)):
        reason = "compressed file is incomplete or corrupt"
    else:
        reason = f"unreadable ({exc.__class__.__name__})"
    label = display_label or path.name
    return f"{label} could not be read - {reason}; skipping"


def _permission_denied_message(path: Path) -> str:
    """Return an actionable permission-denied message for one log file."""
    try:
        st = os.stat(path)
    except OSError:
        return (
            f"{path.name}: permission denied - grant your user read "
            "access and retry"
        )

    if grp is None or pwd is None:
        # Non-POSIX: name lookups and the usermod remedy are POSIX-only, so
        # fall back to numeric owner/group ids and a generic remedy.
        mode = f"{stat.S_IMODE(st.st_mode):04o}"
        return (
            f"{path.name}: permission denied - owned "
            f"{st.st_uid}:{st.st_gid} (mode {mode}); grant your user read "
            "access to it and retry"
        )

    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
        if (st.st_mode & stat.S_IRGRP) and group in _LOG_READER_GROUPS:
            # A new login session is required for group membership to take
            # effect. Do not suggest running sigwood through sudo: a venv's
            # console script may be off root's PATH, and running the security
            # tool as root is poor practice. This sudo changes membership only.
            remedy = (
                f"add your user to the '{group}' group "
                f"(sudo usermod -aG {group} $USER) and log back in"
            )
        else:
            remedy = (
                "grant your user read access to it (adjust its group "
                "ownership or add an ACL) and retry"
            )
    except KeyError:
        group = str(st.st_gid)
        remedy = "grant your user read access to it and retry"

    mode = f"{stat.S_IMODE(st.st_mode):04o}"
    return (
        f"{path.name}: permission denied - owned {owner}:{group} "
        f"(mode {mode}); {remedy}"
    )


def _cloudtrail_parse_warning(path: Path) -> str:
    """Return a privacy-safe warning for a CloudTrail file with malformed JSON.

    Parallels ``_zeek_file_read_warning``'s tone for I/O failures; this variant
    covers the parse-failure case (file readable, but the contents are not JSON
    we can use).
    """
    return f"{path.name} could not be read - not valid JSON; skipping"


def _zeek_file_parse_warning(path: Path, exc: BaseException) -> str:
    """Return a privacy-safe warning for a frame-mode file whose parse failed whole.

    Covers content failures the read rail cannot see (file readable, but e.g. a
    Zeek TSV header is malformed); the file is skipped, the run continues.
    """
    return f"{path.name} could not be parsed - {exc}; skipping"


def _zeek_bad_lines_warning(path: Path, bad_lines: list[tuple[int, str]]) -> str:
    """Return a privacy-safe warning for malformed data lines skipped in one file.

    ``bad_lines`` entries are ``(file_absolute_lineno, reason)`` pairs from the
    tolerant TSV parse - a routine state of a live/mid-write file. One warning
    per file; the first entry's line number anchors it.
    """
    n = len(bad_lines)
    return (
        f"{path.name}: skipped {n} {plural(n, 'malformed line')} "
        f"(first at line {bad_lines[0][0]})"
    )


def _zeek_no_records_warning(path: Path) -> str:
    """Return a warning for a read file that produced zero Zeek records.

    Fires when at least one data line existed but nothing parsed to a usable
    record (non-Zeek text, malformed NDJSON, or rows without ``ts``). An empty
    or header-only file is absence, not unreadable data, and stays silent.
    """
    return f"{path.name}: no Zeek records found - is this a Zeek log?"
