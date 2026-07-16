"""Content sniffing - the digest schema cascade and the syslog content gate.

Two deliberately separate sniff heads (do NOT unify - dnsmasq IS RFC
3164): ``sniff_format`` / ``sniff_format_detailed`` (the digest recognizer
cascade) and ``_looks_like_syslog`` (the syslog discovery content gate).
``_open_log`` is reached through the package facade so test monkeypatches of
``sigwood.common.loader._open_log`` take effect here.
"""

from __future__ import annotations

import gzip
import itertools
import lzma
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import sigwood.common.loader as _loader  # facade: _open_log patch-through (call-time only)
from sigwood.parsers import (
    cloudtrail as _cloudtrail_parser,
    dnsmasq as _dnsmasq_parser,
    syslog as _syslog_parser,
    zeek as _zeek_parser,
    zeek_tsv as _zeek_tsv_parser,
)


def _is_ndjson(path: Path) -> bool:
    """Return True if the file's first content line starts with '{' (NDJSON)."""
    with _loader._open_log(path) as fh:
        for line in fh:
            s = line.strip()
            if s and not s.startswith("#"):
                return s.startswith("{")
    return False


# Byte-bounded prefix read by the syslog content-sniff gate. The bound is
# critical: a line-bounded peek would read a newline-sparse binary
# (wtmp/btmp/lastlog) to EOF; a byte-bounded read cannot (blob's
# hard-bounded-window rail).
_SYSLOG_SNIFF_BYTES = 8192


def _looks_binary(path: Path) -> bool:
    """Return True if a bounded prefix of ``path`` reads as binary / undecodable.

    Guards the flat (syslog / pihole) load path: an explicit flat file or a
    ``pihole*.log*`` glob hit can be a binary (a ``.log.zst``, a misnamed image)
    that ``errors="replace"`` would otherwise smear into "syslog soup" for
    drain3. ``_open_log`` always decodes utf-8 with ``errors="replace"`` (io.py),
    so an undecodable byte becomes U+FFFD; a real text log carries ~none.

    True iff the prefix holds a NUL (high-entropy binary) OR the replacement-char
    density exceeds 30% (NUL-free invalid-UTF8 - e.g. raw zstd, which has no
    stdlib opener pre-3.14 and falls to the plain text open). 30% clears a few
    stray non-UTF8 bytes (a Latin-1 hostname) without flagging a real log.

    Conservative on a read error - return False (NOT binary) so a corrupt
    compressed file defers to ``run_load``'s disclosed read-corruption rail
    (``_zeek_file_read_warning``) rather than being mislabeled binary. This is
    the deliberate OPPOSITE of ``_looks_like_syslog``'s include-on-error default
    (do NOT unify the two).
    """
    try:
        with _loader._open_log(path) as fh:
            chunk = fh.read(_SYSLOG_SNIFF_BYTES)
    except PermissionError:
        raise
    except (EOFError, gzip.BadGzipFile, lzma.LZMAError, OSError):
        return False
    return "\x00" in chunk or chunk.count(chr(0xFFFD)) / max(len(chunk), 1) > 0.30


def _looks_like_syslog(path: Path) -> bool:
    """Content-sniff gate: True iff a BOUNDED decompressed prefix of ``path``
    reads as flat RFC 3164 or ISO-8601 syslog.

    Byte-bounded printable gate FIRST, then the syslog recognizer DIRECTLY - NOT
    the full ``sniff_format`` cascade. Rationale: dnsmasq lines ARE RFC 3164 and
    ``dnsmasq.sniff`` is strict, so the cascade would route a dnsmasq-query-first
    ``messages`` to "dns"; the syslog recognizer claims RFC-3164 headers
    (including dnsmasq's) and ISO-8601 syslog headers carrying a terminated
    program tag, while rejecting ISO-timestamped ``dnf``/``hawkey``, systemd
    ``boot.log``, and binaries.

    Conservative-include on a read error: return True so the file defers to
    ``run_load``'s disclosed corruption rail (``_zeek_file_read_warning``) rather
    than being silently dropped. A gzip rotation decompresses CLEAN through
    ``_open_log``, so the NUL test runs on decoded text - never on raw compressed
    bytes.
    """
    try:
        with _loader._open_log(path) as fh:
            chunk = fh.read(_SYSLOG_SNIFF_BYTES)
    except (EOFError, gzip.BadGzipFile, lzma.LZMAError, OSError):
        return True
    if "\x00" in chunk:
        return False
    lines = chunk.splitlines()
    return _syslog_parser.sniff(lines[: _syslog_parser.SNIFF_PEEK_LINES]) is not None


# Per-parser recognizers in fixed precedence - most-specific-first. The
# orchestrator runs each in turn; first non-None target wins. Precedence is
# the ambiguity policy: zeek_tsv before cloudtrail because the TSV header
# is the strongest signal; cloudtrail before zeek (NDJSON) so CloudTrail
# events are not claimed by the looser Zeek key-set test; dnsmasq before
# syslog because dnsmasq IS RFC 3164 and would otherwise be claimed as
# generic syslog.
_SNIFF_RECOGNIZERS: tuple[tuple[Any, int], ...] = (
    (_zeek_tsv_parser, _zeek_tsv_parser.SNIFF_PEEK_LINES),
    (_cloudtrail_parser, _cloudtrail_parser.SNIFF_PEEK_LINES),
    (_zeek_parser, _zeek_parser.SNIFF_PEEK_LINES),
    (_dnsmasq_parser, _dnsmasq_parser.SNIFF_PEEK_LINES),
    (_syslog_parser, _syslog_parser.SNIFF_PEEK_LINES),
)

_SNIFF_MAX_PEEK: int = max(b for _, b in _SNIFF_RECOGNIZERS)

# Winning-recognizer module → source-family origin. The CLI uses origin to
# split Zeek-dns from Pi-hole-dns without re-reading the file.
_SNIFF_ORIGIN: dict[Any, str] = {
    _zeek_tsv_parser: "zeek",
    _zeek_parser: "zeek",
    _cloudtrail_parser: "cloudtrail",
    _dnsmasq_parser: "pihole",
    _syslog_parser: "syslog",
}


def sniff_format(path: Path) -> str:
    """Classify a log file into a digest schema by sampling its head.

    Opens ``path`` via ``_open_log`` (gzip-transparent), reads at most
    ``_SNIFF_MAX_PEEK`` lines once, and runs the per-parser recognizers in
    fixed precedence (zeek_tsv → cloudtrail → zeek → dnsmasq → syslog).
    Each recognizer sees only the prefix it asked for via ``SNIFF_PEEK_LINES``.

    Returns one of "conn" | "dns" | "syslog" | "cloudtrail" | "blob". The
    "blob" floor covers empty files and any content no recognizer claims.

    This function classifies content only - the CLI-level decision of how
    to handle empty inputs is layered on top in a later stage and is not
    pre-empted here.
    """
    with _loader._open_log(path) as fh:
        sample = list(itertools.islice(fh, _SNIFF_MAX_PEEK))
    if not sample:
        return "blob"
    for mod, budget in _SNIFF_RECOGNIZERS:
        target = mod.sniff(sample[:budget])
        if target is not None:
            return target
    return "blob"


@dataclass(frozen=True)
class SniffResult:
    """Detailed sniff outcome - schema plus source-family origin.

    ``state`` is "empty" or "classified". On "empty", ``schema`` and ``origin``
    are both None. On "classified", ``schema`` is one of
    {conn, dns, syslog, cloudtrail, blob}; ``origin`` is the winning
    recognizer's source family ({zeek, pihole, syslog, cloudtrail}) when a
    recognizer claimed the sample, or None on the blob floor.
    """

    state: str
    schema: str | None
    origin: str | None


def sniff_format_detailed(path: Path) -> SniffResult:
    """Classify a log file and expose origin + empty-state.

    Sibling to ``sniff_format``. Single bounded read (``_SNIFF_MAX_PEEK`` lines
    plus a one-line EOF probe). The CLI uses the result to short-circuit
    truly-empty files and to split Zeek-dns vs Pi-hole-dns by origin.

    Empty-detection contract is EOF-sensitive (leading whitespace beyond the
    peek does not classify as empty):

    1. Zero-byte file → state="empty" without opening.
    2. Sample length zero → state="empty".
    3. Every sampled line is whitespace-only AND EOF was reached within the
       bounded read → state="empty".
    4. Every sampled line is whitespace-only AND EOF was NOT reached (file
       has more content beyond the peek) → fall through to the recognizer
       cascade; the blob floor catches it.

    Otherwise the same precedence as ``sniff_format``; origin is mapped from
    the winning recognizer module via ``_SNIFF_ORIGIN``. Blob floor returns
    ``schema="blob"``, ``origin=None``.
    """
    if path.stat().st_size == 0:
        return SniffResult(state="empty", schema=None, origin=None)
    with _loader._open_log(path) as fh:
        sample = list(itertools.islice(fh, _SNIFF_MAX_PEEK))
        # One-line EOF probe - at most _SNIFF_MAX_PEEK + 1 lines read total.
        eof_reached = next(fh, None) is None
    if not sample:
        return SniffResult(state="empty", schema=None, origin=None)
    if eof_reached and all(not line.strip() for line in sample):
        return SniffResult(state="empty", schema=None, origin=None)
    for mod, budget in _SNIFF_RECOGNIZERS:
        target = mod.sniff(sample[:budget])
        if target is not None:
            return SniffResult(
                state="classified",
                schema=target,
                origin=_SNIFF_ORIGIN[mod],
            )
    return SniffResult(state="classified", schema="blob", origin=None)
