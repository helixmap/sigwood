"""Zeek NDJSON log normalization - column maps and normalize functions for conn and dns logs."""

import json

import pandas as pd

# Zeek conn log column → canonical name. Only columns that need renaming are listed.
# Columns that already have canonical names (proto, ts, conn_state, local_orig) are absent.
_CONN_COLUMN_MAP: dict[str, str] = {
    "id.orig_h":  "src",
    "id.resp_h":  "dst",
    "id.resp_p":  "port",
    "orig_bytes": "bytes",
}

# Zeek dns log → canonical DNS schema.
# Renames: TTLs→ttl, answers→answer, TC→tc, id.orig_h→src,
# id.resp_h→resolver.
# rtt, rcode, and qtype are already canonical (qtype as Zeek's raw numeric
# type code, e.g. 1 = A, 28 = AAAA); qclass is filtered (aperture) and
# dropped - see _normalize_dns_df.
# Canonical minimal schema: ts, src, query.
# Canonical extended schema (nullable): resolver, qtype, rtt, ttl, rcode,
# answer, tc.
_DNS_COLUMN_MAP: dict[str, str] = {
    "id.orig_h": "src",
    "id.resp_h": "resolver",
    "TTLs":      "ttl",
    "answers":   "answer",
    "TC":        "tc",
}

_REQUIRED_COLUMNS: dict[str, set[str]] = {
    "conn": {"src", "dst", "port", "proto", "ts", "duration"},
    "dns": {"src", "query", "ts"},
    "syslog": {"ts", "host", "program", "raw", "message"},
}

# Canonical but nullable fields: present in _REQUIRED_COLUMNS for documentation,
# but absent from real logs without error (e.g. Zeek omits duration for open connections).
# Add new nullable canonical fields here, not to _REQUIRED_COLUMNS alone, so
# _schema_warning never fires for expected-absent columns.
_OPTIONAL_COLUMNS: dict[str, set[str]] = {
    "conn": {"duration", "bytes", "conn_state", "local_orig"},
    "dns":  {"resolver", "qtype", "rtt", "ttl", "rcode", "answer", "tc"},
    # syslog extended (Zeek-only): facility/severity carried as-is from Zeek
    # (uppercase enum strings, e.g. "DAEMON" / "INFO"). The digest consumes
    # severity; the detector is source-blind.
    "syslog": {"facility", "severity"},
}


def _normalize_conn_df(df: pd.DataFrame) -> pd.DataFrame:
    """Rename Zeek conn log columns to the canonical schema. Only renames columns that exist."""
    rename = {k: v for k, v in _CONN_COLUMN_MAP.items() if k in df.columns}
    return df.rename(columns=rename) if rename else df


def _normalize_zeek_syslog_df(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize Zeek syslog.log to the canonical fidelity-aware syslog schema.

    Minimal (always present on the happy path; v1-required):
        ts, host, program, raw, message
    Extended (Zeek-only, nullable):
        facility, severity - uppercase enum strings (e.g. "DAEMON", "INFO"),
        carried as-is for consumer interpretation. The digest reads severity
        (error-set {EMERG, ALERT, CRIT, ERR}); the detector is source-blind
        and never references either column.

    Per-row derivation (happy path):
        raw     = Zeek `message` verbatim (drives finding title)
        host    = embedded RFC 3164 hostname via parse_host(raw); falls back
                  to Zeek `id.orig_h` when parse_host returns "unknown"
        program = parse_program(strip_header(raw))
        message = normalize_pids(strip_header(raw))  # canonical, drain3-aligned
        ts      = Zeek ts (already canonical epoch float)

    Malformed-frame path: when input lacks `message`, the normalizer does
    NOT synthesize message/raw/program just to satisfy shape - that would
    paint a confident-but-empty card. The output frame omits the columns
    that cannot be derived; loader._schema_warning then fires the
    actionable "syslog.log fields not found" warning.

    Drops uid/id.orig_p/id.resp_h/id.resp_p/proto and id.orig_h (the latter
    after being consumed as the host fallback). Reuses the RFC 3164 helpers
    in parsers/syslog.py so the doubled-timestamp invariant (^-anchored
    strip_header strips only the leading transport header) holds for both
    feeds.
    """
    from sigwood.parsers.syslog import (
        normalize_pids,
        parse_host,
        parse_program,
        strip_header,
    )

    drop_cols = {"uid", "id.orig_h", "id.orig_p",
                 "id.resp_h", "id.resp_p", "proto"}

    if "message" not in df.columns:
        # Honesty rail: preserve absence so _schema_warning fires.
        keep = [c for c in df.columns if c not in drop_cols]
        return df[keep].copy() if keep else df.copy()

    # Narrow trailing-line-terminator strip: Zeek's NDJSON `message` field can
    # carry the upstream record's trailing "\r"/"\n" (observed: 15,995 of one
    # production capture). The detector uses raw as a single-line finding title;
    # an embedded trailing "\n" then renders as a blank spacer row beneath the
    # finding. Mirrors flat load_syslog's `line.rstrip("\n")` at the file-line
    # boundary - same contract for the canonical column, applied once at the
    # canonical seam.
    # str.rstrip("\r\n") treats the arg as a CHARSET, so any mix of trailing
    # CR/LF is removed; embedded mid-line newlines would survive verbatim,
    # preserving fidelity.
    raw = df["message"].astype(str).str.rstrip("\r\n")
    stripped = raw.map(strip_header)

    embedded_host = raw.map(parse_host)
    if "id.orig_h" in df.columns:
        host = embedded_host.where(embedded_host != "unknown", df["id.orig_h"])
    else:
        host = embedded_host

    out = pd.DataFrame({
        "ts":      df["ts"] if "ts" in df.columns else pd.Series(dtype="float64"),
        "host":    host,
        "program": stripped.map(parse_program),
        "raw":     raw,
        "message": stripped.map(normalize_pids),
    })
    if "facility" in df.columns:
        out["facility"] = df["facility"].values
    if "severity" in df.columns:
        out["severity"] = df["severity"].values

    return out


def _normalize_dns_df(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize Zeek dns.log to the canonical DNS schema.

    Renames TTLs→ttl, answers→answer, TC→tc, id.orig_h→src, and
    id.resp_h→resolver.
    Applies the internet-class aperture (qclass == 1) and drops qclass.
    Carries qtype through as Zeek's raw numeric type code (e.g. 1 = A,
    28 = AAAA); consumers wanting mnemonics map them downstream.
    """
    rename = {k: v for k, v in _DNS_COLUMN_MAP.items() if k in df.columns}
    if rename:
        df = df.rename(columns=rename)

    if "qclass" in df.columns:
        df = df[df["qclass"] == 1]  # keeps only internet-class; == 1 already drops nulls
        df = df.drop(columns=["qclass"])

    return df


SNIFF_PEEK_LINES: int = 4


def _has_rename_collision(keys, column_map: dict[str, str]) -> bool:
    """True iff any (zeek_key, canonical) pair in column_map has BOTH the
    zeek key AND its canonical rename target present in `keys`.

    A clean Zeek conn/dns NDJSON without `_path` carries the `id.*` keys
    and never a native `src`/`dst`/`port`. A record carrying both halves
    of any rename pair (e.g. `id.orig_h` AND `src`) would produce a
    duplicate canonical column when the loader's rename runs, which then
    crashes the downstream summariser - so the record is not a clean
    conn/dns and the field-set fallback must not claim it.
    """
    return any(z in keys and c in keys for z, c in column_map.items())


def sniff(sample: list[str]) -> str | None:
    """Recognize a Zeek NDJSON conn or dns line and return its digester target.

    Parses the first non-empty line of ``sample`` as JSON and inspects its
    keys. Recognition proceeds in two layers:

    1. **``_path`` gate (Zeek-native).** When the parsed dict carries the
       Zeek ``_path`` directive (Zeek's own per-log-type tag, e.g. ``conn``,
       ``dns``, ``syslog``, ``notice``, ``analyzer``, …), trust it directly:
       ``_path == "conn"`` → ``"conn"``; ``_path == "dns"`` → ``"dns"``;
       ``_path == "syslog"`` → ``"syslog"``; any other value → ``None`` (we
       do not have a digester for that log type - fall to the blob floor).
       This is the NDJSON twin of the TSV ``#path`` gate in
       ``zeek_tsv.sniff``; non-claimable Zeek logs (notice.log,
       analyzer.log) carry the 5-tuple as connection context but are NOT
       conn frames and must not be claimed as such.

    2. **Field-set fallback (Zeek NDJSON without ``_path``, hand-rolled
       NDJSON).** When ``_path`` is absent, fall through to field-set tests
       in this fixed order:

         a. **dns** when the line carries the DNS key set (``query`` +
            ``src``/``id.orig_h`` + ``ts``).
         b. **syslog** when the line carries facility + severity + message
            + ts + ``src``/``id.orig_h``. The three syslog-specific keys
            (facility/severity/message) together are a tight signature -
            neither ``notice.log`` nor ``analyzer.log`` carries that
            triple, so the false-claim risk from sharing the 5-tuple does
            NOT recur. Required to sit BEFORE the conn fallback: a Zeek
            syslog.log emitted without ``_path`` carries the 5-tuple in
            addition to the syslog fields, and the conn fallback would
            otherwise claim it.
         c. **conn** when it carries the conn key set (src/dst/port/proto/
            ts via either native or canonical names) AND ``query`` is
            absent - "no query" is the explicit disambiguator from DNS.

       Returns None when none of the key sets matches.

    Returns None for non-JSON, JSON that is not a dict, and dicts lacking
    either signal.

    ``duration`` is NOT required for conn - it is optional (Zeek omits it
    for open connections); see _OPTIONAL_COLUMNS.

    Pure: takes already-decoded lines, performs no I/O.
    """
    for raw_line in sample:
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return None
        if not isinstance(obj, dict):
            return None
        keys = obj.keys()

        # Layer 1: _path gate - Zeek emits this on every native log line.
        # Trust it directly and reject anything that isn't conn or dns.
        if "_path" in keys:
            path = obj.get("_path")
            if path == "conn":
                return "conn"
            if path == "dns":
                return "dns"
            if path == "syslog":
                return "syslog"
            return None

        # Layer 2: field-set fallback for Zeek NDJSON emitted without _path
        # and for hand-rolled non-Zeek NDJSON.
        has_src = "src" in keys or "id.orig_h" in keys
        has_ts = "ts" in keys

        # 2a. dns: query is the disambiguator. Rejected when the record
        # also carries a Zeek-native key whose canonical rename target is
        # already present (e.g. id.orig_h + native src) - that collision
        # would crash the dns summariser at rename time.
        if (
            has_src
            and has_ts
            and "query" in keys
            and not _has_rename_collision(keys, _DNS_COLUMN_MAP)
        ):
            return "dns"

        # 2b. syslog: facility + severity + message form a tight Zeek-syslog
        # signature. MUST sit before the conn fallback - Zeek syslog.log
        # without `_path` carries the 5-tuple alongside the syslog fields,
        # so the conn fallback would otherwise claim it as conn. Notice and
        # analyzer logs DO NOT carry the (facility, severity, message)
        # triple, so this does not reopen the notice/analyzer false-claim.
        if (
            has_src
            and has_ts
            and "facility" in keys
            and "severity" in keys
            and "message" in keys
        ):
            return "syslog"

        # 2c. conn: full 5-tuple, no query. Rejected when the record
        # also carries a Zeek-native key whose canonical rename target
        # is already present (e.g. id.orig_h + native src, the
        # notice.log shape) - that collision would crash the conn
        # summariser with the "Grouper for 'src' not 1-dimensional"
        # pandas error.
        has_dst = "dst" in keys or "id.resp_h" in keys
        has_port = "port" in keys or "id.resp_p" in keys
        has_proto = "proto" in keys
        if (
            has_src
            and has_dst
            and has_port
            and has_proto
            and has_ts
            and "query" not in keys
            and not _has_rename_collision(keys, _CONN_COLUMN_MAP)
        ):
            return "conn"
        return None
    return None
