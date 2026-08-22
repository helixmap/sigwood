"""Zeek TSV log parser - header-block parsing and type coercion.

This module is the TSV front-end for Zeek log parsing. It produces a pre-normalization
DataFrame with Zeek-native column names and Python-typed values, ready for consumption
by the normalizers in parsers/zeek.py (_normalize_conn_df, _normalize_dns_df).

Architecture: one normalizer, two front-ends. The NDJSON front-end (common/loader.py)
and this TSV front-end both produce the same intermediate DataFrame shape. Normalizers
are never aware of which format was loaded.

File I/O and decompression are the caller's responsibility (common/loader.py, stage 2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

import pandas as pd

# Sentinel returned by _coerce when a field value is the unset token.
# The caller must omit the key from the record dict entirely.
# Using absent keys (rather than explicit None) mirrors the NDJSON path:
# pd.DataFrame(records) produces NaN for absent keys, matching NDJSON absent-field behavior.
_UNSET = object()


@dataclass
class _TSVHeader:
    """Parsed Zeek TSV header block directives."""

    separator: str = "\t"
    set_separator: str = ","        # Zeek spec default
    empty_field: str = "(empty)"    # Zeek spec default
    unset_field: str = "-"          # Zeek spec default
    path: str = ""
    fields: list[str] = field(default_factory=list)
    types: list[str] = field(default_factory=list)

    # Tracks whether #separator was actually declared (required).
    _separator_seen: bool = field(default=False, repr=False)


def _unescape_separator(raw: str) -> str:
    """Convert Zeek #separator escape sequences (e.g. \\x09) to real characters."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), raw)


SNIFF_PEEK_LINES: int = 16


def sniff(sample: list[str]) -> str | None:
    """Recognize a Zeek TSV header and return its digester target.

    Returns "conn", "dns", "syslog", "ssl", "x509", or "weird" when the sample
    carries a well-formed Zeek TSV header block declaring #separator, #fields,
    and #path with one of those values. Returns None for any other shape -
    including text that happens to contain a "#path" substring without a
    real header block, and Zeek TSV logs whose #path is something else
    (notice/analyzer/etc. - no digester yet, fall to the blob floor).

    Pure: takes already-decoded lines, performs no I/O. Mirrors the header
    parse in _parse_header without draining the iterator.
    """
    separator: str | None = None
    path: str | None = None
    fields_seen = False
    saw_directive = False

    for raw_line in sample:
        line = raw_line.rstrip("\r\n")
        if not line:
            continue
        if not line.startswith("#"):
            break
        saw_directive = True
        if line.startswith("#separator ") or line.startswith("#separator\t"):
            raw_val = line.split(None, 1)[1].strip()
            separator = _unescape_separator(raw_val)
            continue
        if separator is None:
            # Other directives use the parsed separator; without #separator
            # we cannot split them. Skip - #separator may yet appear.
            continue
        parts = line[1:].split(separator)
        key = parts[0]
        values = parts[1:]
        if key == "path":
            path = values[0] if values else ""
        elif key == "fields":
            fields_seen = True

    if not saw_directive or separator is None or not fields_seen:
        return None
    if path == "conn":
        return "conn"
    if path == "dns":
        return "dns"
    if path == "syslog":
        return "syslog"
    if path == "ssl":
        return "ssl"
    if path == "x509":
        return "x509"
    if path == "weird":
        return "weird"
    return None


def _parse_header(lines: Iterator[str]) -> tuple[_TSVHeader, list[tuple[int, str]]]:
    """Parse the Zeek TSV header block and return (header, buffered data lines).

    Reads #-prefixed directive lines until the first non-# line or #close.
    The first non-# line is the first data row; it is included in the buffer.

    Buffered entries are ``(abs_lineno, line)`` pairs where ``abs_lineno`` is the
    FILE-ABSOLUTE line number - every line consumed from the iterator counts
    (directives, blanks, ``#close`` alike). Blank lines are dropped from the
    buffer, so a data-region index cannot recover file positions; the pairs
    carry them.

    Raises ValueError if #fields or #types is missing, their lengths differ,
    or #separator was never declared before data rows appear.
    """
    hdr = _TSVHeader()
    data_lines: list[tuple[int, str]] = []
    abs_lineno = 0

    for raw_line in lines:
        abs_lineno += 1
        line = raw_line.rstrip("\r\n")

        if not line:
            continue

        if line.startswith("#separator ") or line.startswith("#separator\t"):
            # #separator uses plain space as its own delimiter.
            raw_val = line.split(None, 1)[1].strip()
            hdr.separator = _unescape_separator(raw_val)
            hdr._separator_seen = True
            continue

        if line.startswith("#close"):
            break

        if line.startswith("#"):
            # All other directives use the declared separator.
            parts = line[1:].split(hdr.separator)
            key = parts[0]
            values = parts[1:]

            if key == "set_separator":
                hdr.set_separator = values[0] if values else ","
            elif key == "empty_field":
                hdr.empty_field = values[0] if values else "(empty)"
            elif key == "unset_field":
                hdr.unset_field = values[0] if values else "-"
            elif key == "path":
                hdr.path = values[0] if values else ""
            elif key == "fields":
                hdr.fields = values
            elif key == "types":
                hdr.types = values
            # #open and other directives are silently ignored.
            continue

        # First non-# line: data row.
        if not hdr._separator_seen:
            raise ValueError("Zeek TSV header missing #separator")
        data_lines.append((abs_lineno, line))
        break

    # Drain remaining lines.
    for raw_line in lines:
        abs_lineno += 1
        line = raw_line.rstrip("\r\n")
        if line.startswith("#close"):
            break
        if line:
            data_lines.append((abs_lineno, line))

    # Validate required directives.
    if not hdr.fields:
        raise ValueError("Zeek TSV header missing #fields")
    if not hdr.types:
        raise ValueError("Zeek TSV header missing #types")
    if len(hdr.fields) != len(hdr.types):
        raise ValueError(
            f"Zeek TSV #fields has {len(hdr.fields)} columns but "
            f"#types has {len(hdr.types)} - header is malformed"
        )

    return hdr, data_lines


# Container-type prefix regex for set[…] and vector[…].
_CONTAINER_RE = re.compile(r"^(?:set|vector)\[(.+)\]$")

# Known scalar Zeek types. Anything not in this set or not a container raises.
_SCALAR_TYPES = frozenset({
    "time", "interval", "double",
    "count", "int", "port",
    "bool",
    "addr", "string", "enum",
})

# Zeek emits single-level set/vector values. This structural cap leaves ample
# headroom for nested containers without tying acceptance to runtime recursion.
_MAX_CONTAINER_DEPTH = 8


def _coerce(
    raw: str,
    zeek_type: str,
    set_sep: str,
    empty_field: str,
    unset_field: str,
    *,
    _depth: int = 0,
) -> Any:
    """Coerce a raw TSV field value to its Python equivalent for the given Zeek type.

    Returns _UNSET when the value is the unset token - the caller must omit the key
    from the record dict rather than inserting None.

    Raises ValueError for unknown types, invalid bool tokens, empty tokens on numeric
    or bool types, and _UNSET appearing inside a collection element.
    """
    if raw == unset_field:
        return _UNSET

    # Container types: set[inner] and vector[inner].
    m = _CONTAINER_RE.match(zeek_type)
    if m:
        if raw == empty_field:
            return []
        if _depth >= _MAX_CONTAINER_DEPTH:
            raise ValueError(
                f"Zeek TSV: container nesting exceeds {_MAX_CONTAINER_DEPTH}; "
                f"at most {_MAX_CONTAINER_DEPTH} nested set/vector wrappers "
                "are accepted"
            )
        inner_type = m.group(1)
        result = []
        for element in raw.split(set_sep):
            coerced = _coerce(
                element,
                inner_type,
                set_sep,
                empty_field,
                unset_field,
                _depth=_depth + 1,
            )
            if coerced is _UNSET:
                raise ValueError(
                    f"Zeek TSV: unset token found inside collection element "
                    f"(type {zeek_type!r}); individual elements cannot be unset"
                )
            result.append(coerced)
        return result

    # Scalar types.
    if zeek_type in ("time", "interval", "double"):
        if raw == empty_field:
            raise ValueError(
                f"Zeek TSV: empty token in numeric field (type {zeek_type!r})"
            )
        return float(raw)

    if zeek_type in ("count", "int", "port"):
        if raw == empty_field:
            raise ValueError(
                f"Zeek TSV: empty token in numeric field (type {zeek_type!r})"
            )
        return int(raw)

    if zeek_type == "bool":
        if raw == empty_field:
            raise ValueError("Zeek TSV: empty token in bool field")
        if raw == "T":
            return True
        if raw == "F":
            return False
        raise ValueError(
            f"Zeek TSV: invalid bool token {raw!r} - expected 'T' or 'F'"
        )

    if zeek_type in ("addr", "string", "enum"):
        return "" if raw == empty_field else raw

    raise ValueError(f"Zeek TSV: unsupported Zeek type {zeek_type!r}")


def parse_tsv_log(
    source: Iterable[str],
    *,
    bad_lines: list[tuple[int, str]] | None = None,
) -> pd.DataFrame:
    """Parse a single Zeek TSV log stream and return a pre-normalization DataFrame.

    source may be an open text stream or any iterable of strings (e.g. the result of
    str.splitlines(keepends=True)).

    Column names retain Zeek-native names (id.orig_h, id.resp_p, TTLs, answers, etc.).
    Values are typed as Python objects matching what json.loads produces on the NDJSON
    path: floats for time/interval/double, ints for count/int/port, bools for bool,
    lists for set[…]/vector[…], absent key for unset fields.

    This output is intended to be passed directly to _normalize_conn_df or
    _normalize_dns_df in sigwood.parsers.zeek, unchanged.

    bad_lines is the opt-in tolerance sink for live/mid-write files: when a list is
    passed, each ragged or uncoercible DATA line is skipped and recorded in it as
    ``(file_absolute_lineno, reason)`` while parsing continues. Header errors raise
    regardless - a broken header means no row can be trusted. Blank and #-comment
    lines in the data region are skipped-not-malformed in both modes.

    Raises ValueError for malformed headers (always) and - when bad_lines is None
    (the strict default) - for ragged rows, invalid coercions, or unknown Zeek types.
    """
    hdr, data_lines = _parse_header(iter(source))

    n_fields = len(hdr.fields)
    records: list[dict[str, Any]] = []

    for data_idx, (abs_lineno, line) in enumerate(data_lines, start=1):
        # Strip any residual line endings (header parser may have left some if
        # data_lines were collected after the first data row was already stripped).
        line = line.rstrip("\r\n")
        if not line or line.startswith("#"):
            continue

        tokens = line.split(hdr.separator)
        if len(tokens) != n_fields:
            if bad_lines is not None:
                bad_lines.append(
                    (abs_lineno, f"has {len(tokens)} fields, expected {n_fields}")
                )
                continue
            # Strict mode keeps the data-region-relative line number in the
            # message; only sink entries carry file-absolute numbers.
            raise ValueError(
                f"Zeek TSV: line {data_idx} has {len(tokens)} fields, "
                f"expected {n_fields}"
            )

        record: dict[str, Any] = {}
        try:
            for fname, ftype, raw in zip(hdr.fields, hdr.types, tokens):
                value = _coerce(
                    raw, ftype, hdr.set_separator, hdr.empty_field, hdr.unset_field
                )
                if value is not _UNSET:
                    record[fname] = value
        except ValueError as exc:
            if bad_lines is None:
                raise
            bad_lines.append((abs_lineno, str(exc)))
            continue

        records.append(record)

    if not records:
        return pd.DataFrame(columns=hdr.fields)

    return pd.DataFrame(records)
