"""Parity, directive-behavior, and smoke tests for sigwood.parsers.zeek_tsv.

All fixture data is hand-authored using RFC 5737 documentation IP space
(192.0.2.x, 198.51.100.x, 203.0.113.x). No real network data anywhere.
"""

from __future__ import annotations

import json
import math

import pandas as pd
import pytest

from sigwood.parsers.zeek import _normalize_conn_df, _normalize_dns_df
from sigwood.parsers.zeek_tsv import parse_tsv_log

# ── Fixture constants ─────────────────────────────────────────────────────────
#
# Every fixture is a raw string to be passed as splitlines(keepends=True).
# Tab characters are written as literal tabs. RFC 5737 IPs throughout.

_CONN_TSV = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
    "\tproto\tservice\tduration\torig_bytes\tresp_bytes"
    "\tconn_state\tlocal_orig\tlocal_resp\ttunnel_parents\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport"
    "\tenum\tstring\tinterval\tcount\tcount"
    "\tstring\tbool\tbool\tset[string]\n"
    # Row A: duration present, service present, local_orig=T, tunnel_parents=(empty)
    "1748649600.000000\tCTest01\t192.0.2.10\t51514\t203.0.113.20\t443"
    "\ttcp\tssl\t3.5\t1500\t8200\tSF\tT\tF\t(empty)\n"
    # Row B: duration unset, service unset, local_orig=F, tunnel_parents unset
    "1748649660.000000\tCTest02\t198.51.100.1\t54321\t192.0.2.20\t22"
    "\ttcp\t-\t-\t0\t0\tS0\tF\tF\t-\n"
    "#close\t2026-01-01-00:00:00\n"
)

# Equivalent events in NDJSON. Absent keys mirror TSV unset tokens.
_CONN_NDJSON = (
    '{"ts":1748649600.0,"uid":"CTest01","id.orig_h":"192.0.2.10","id.orig_p":51514,'
    '"id.resp_h":"203.0.113.20","id.resp_p":443,"proto":"tcp","service":"ssl",'
    '"duration":3.5,"orig_bytes":1500,"resp_bytes":8200,"conn_state":"SF",'
    '"local_orig":true,"local_resp":false,"tunnel_parents":[]}\n'
    '{"ts":1748649660.0,"uid":"CTest02","id.orig_h":"198.51.100.1","id.orig_p":54321,'
    '"id.resp_h":"192.0.2.20","id.resp_p":22,"proto":"tcp",'
    '"orig_bytes":0,"resp_bytes":0,"conn_state":"S0",'
    '"local_orig":false,"local_resp":false}\n'
)

_DNS_TSV = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tdns\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
    "\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name"
    "\trcode\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport"
    "\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring"
    "\tcount\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool\n"
    # Row 1: qclass=1, multi-value answers/TTLs, rtt present, AA=T, TC=F
    "1748649700.000000\tCDns01\t192.0.2.1\t12345\t192.0.2.53\t53"
    "\tudp\t1001\t0.050000\talpha.invalid\t1\tC_INTERNET\t1\tA"
    "\t0\tT\tF\tT\tT\t0\t198.51.100.1,203.0.113.1\t300.000000,300.000000\tF\n"
    # Row 2: qclass=2 - dropped by normalizer aperture
    "1748649701.000000\tCDns02\t192.0.2.2\t12346\t192.0.2.53\t53"
    "\tudp\t1002\t0.030000\tbeta.invalid\t2\tC_CSNET\t1\tA"
    "\t0\tF\tF\tT\tT\t0\t198.51.100.2\t60.000000\tF\n"
    # Row 3: qclass=1, empty query, rtt unset, answers unset, TTLs unset
    "1748649702.000000\tCDns03\t192.0.2.3\t12347\t192.0.2.53\t53"
    "\tudp\t1003\t-\t(empty)\t1\tC_INTERNET\t48\tDNSKEY"
    "\t0\tF\tF\tT\tF\t0\t-\t-\tF\n"
    "#close\t2026-01-01-00:00:00\n"
)

# NDJSON equivalent - qclass=2 row included so the aperture can drop it identically.
_DNS_NDJSON = (
    '{"ts":1748649700.0,"uid":"CDns01","id.orig_h":"192.0.2.1","id.orig_p":12345,'
    '"id.resp_h":"192.0.2.53","id.resp_p":53,"proto":"udp","trans_id":1001,'
    '"rtt":0.05,"query":"alpha.invalid","qclass":1,"qclass_name":"C_INTERNET",'
    '"qtype":1,"qtype_name":"A","rcode":0,"AA":true,"TC":false,"RD":true,"RA":true,'
    '"Z":0,"answers":["198.51.100.1","203.0.113.1"],"TTLs":[300.0,300.0],'
    '"rejected":false}\n'
    '{"ts":1748649701.0,"uid":"CDns02","id.orig_h":"192.0.2.2","id.orig_p":12346,'
    '"id.resp_h":"192.0.2.53","id.resp_p":53,"proto":"udp","trans_id":1002,'
    '"rtt":0.03,"query":"beta.invalid","qclass":2,"qclass_name":"C_CSNET",'
    '"qtype":1,"qtype_name":"A","rcode":0,"AA":false,"TC":false,"RD":true,"RA":true,'
    '"Z":0,"answers":["198.51.100.2"],"TTLs":[60.0],"rejected":false}\n'
    '{"ts":1748649702.0,"uid":"CDns03","id.orig_h":"192.0.2.3","id.orig_p":12347,'
    '"id.resp_h":"192.0.2.53","id.resp_p":53,"proto":"udp","trans_id":1003,'
    '"query":"","qclass":1,"qclass_name":"C_INTERNET",'
    '"qtype":48,"qtype_name":"DNSKEY","rcode":0,"AA":false,"TC":false,'
    '"RD":true,"RA":false,"Z":0,"rejected":false}\n'
)

_SMOKE_TSV = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
    "\tproto\tduration\tlocal_orig\ttunnel_parents\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport"
    "\tenum\tinterval\tbool\tset[string]\n"
    "1748649800.000000\tCSmk01\t192.0.2.10\t11111\t203.0.113.1\t80\ttcp\t1.5\tT\tfoo,bar\n"
    "1748649801.000000\tCSmk02\t192.0.2.11\t22222\t203.0.113.2\t443\ttcp\t-\tF\t-\n"
)


# ── Helper ────────────────────────────────────────────────────────────────────

def _ndjson_df(ndjson: str) -> pd.DataFrame:
    records = [json.loads(ln) for ln in ndjson.strip().splitlines()]
    return pd.DataFrame(records)


def _compare(tsv_df: pd.DataFrame, ndjson_df: pd.DataFrame) -> None:
    """Sort both frames by ts, reset index, compare ignoring column order."""
    left  = tsv_df.sort_values("ts").reset_index(drop=True)
    right = ndjson_df.sort_values("ts").reset_index(drop=True)
    pd.testing.assert_frame_equal(left, right, check_like=True)


# ── Parity tests ──────────────────────────────────────────────────────────────

def test_conn_tsv_ndjson_parity() -> None:
    """TSV and NDJSON conn paths produce identical normalized DataFrames."""
    tsv_df   = _normalize_conn_df(parse_tsv_log(_CONN_TSV.splitlines(keepends=True)))
    ndjson_df = _normalize_conn_df(_ndjson_df(_CONN_NDJSON))
    _compare(tsv_df, ndjson_df)


def test_dns_tsv_ndjson_parity() -> None:
    """TSV and NDJSON dns paths produce identical normalized DataFrames.

    Both paths go through _normalize_dns_df which applies the qclass==1
    aperture. The qclass=2 row must be dropped by both paths identically,
    and the surviving qtype values must pass through as raw numeric type
    codes (1 = A, 48 = DNSKEY) in both paths. The Zeek responder address must
    become canonical `resolver`, never leak as `id.resp_h`.
    """
    tsv_df    = _normalize_dns_df(parse_tsv_log(_DNS_TSV.splitlines(keepends=True)))
    ndjson_df = _normalize_dns_df(_ndjson_df(_DNS_NDJSON))
    assert len(tsv_df) == 2, "qclass=2 row must be dropped"
    # qtype must be present and preserved as raw numeric in both paths.
    assert "qtype" in tsv_df.columns, "qtype must survive TSV normalization"
    assert "qtype" in ndjson_df.columns, "qtype must survive NDJSON normalization"
    assert sorted(tsv_df["qtype"].tolist()) == [1, 48]
    assert sorted(ndjson_df["qtype"].tolist()) == [1, 48]
    assert tsv_df["resolver"].tolist() == ["192.0.2.53", "192.0.2.53"]
    assert ndjson_df["resolver"].tolist() == ["192.0.2.53", "192.0.2.53"]
    assert "id.resp_h" not in tsv_df.columns
    assert "id.resp_h" not in ndjson_df.columns
    _compare(tsv_df, ndjson_df)


# ── Directive-behavior tests ──────────────────────────────────────────────────

def test_non_tab_separator() -> None:
    """Parser honors a non-tab #separator directive."""
    tsv = (
        "#separator \\x7c\n"          # pipe |
        "#set_separator|,\n"
        "#empty_field|(empty)\n"
        "#unset_field|-\n"
        "#path|conn\n"
        "#fields|ts|src\n"
        "#types|time|string\n"
        "1748649600.000000|192.0.2.1\n"
    )
    df = parse_tsv_log(tsv.splitlines(keepends=True))
    assert list(df.columns) == ["ts", "src"]
    assert df.iloc[0]["ts"] == pytest.approx(1748649600.0)
    assert df.iloc[0]["src"] == "192.0.2.1"


def test_custom_empty_and_unset_tokens() -> None:
    """Custom #empty_field and #unset_field tokens are honored."""
    tsv = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\tEMPTY\n"
        "#unset_field\tNONE\n"
        "#path\ttest\n"
        "#fields\tts\ta\tb\n"
        "#types\ttime\tstring\tstring\n"
        "1748649600.0\tEMPTY\tNONE\n"
    )
    df = parse_tsv_log(tsv.splitlines(keepends=True))
    assert df.iloc[0]["a"] == ""          # empty token → empty string
    assert "b" not in df.iloc[0] or math.isnan(df.iloc[0]["b"])  # unset → absent/NaN


def test_custom_set_separator() -> None:
    """Custom #set_separator is used to split set/vector fields."""
    tsv = (
        "#separator \\x09\n"
        "#set_separator\t|\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\ttest\n"
        "#fields\tts\tanswers\n"
        "#types\ttime\tvector[string]\n"
        "1748649600.0\talpha|beta|gamma\n"
    )
    df = parse_tsv_log(tsv.splitlines(keepends=True))
    assert df.iloc[0]["answers"] == ["alpha", "beta", "gamma"]


def test_missing_separator_raises() -> None:
    """A header without #separator followed by a data row raises ValueError."""
    tsv = (
        "#set_separator\t,\n"
        "#fields\tts\tsrc\n"
        "#types\ttime\tstring\n"
        "1748649600.0\t192.0.2.1\n"
    )
    with pytest.raises(ValueError, match="missing #separator"):
        parse_tsv_log(tsv.splitlines(keepends=True))


def test_fields_types_length_mismatch_raises() -> None:
    """Mismatched #fields / #types lengths raise ValueError."""
    tsv = (
        "#separator \\x09\n"
        "#fields\tts\tsrc\tdst\n"
        "#types\ttime\tstring\n"   # only 2 types for 3 fields
    )
    with pytest.raises(ValueError, match="#fields"):
        parse_tsv_log(tsv.splitlines(keepends=True))


def test_missing_fields_raises() -> None:
    """A header with no #fields line raises ValueError."""
    tsv = (
        "#separator \\x09\n"
        "#types\ttime\tstring\n"
        "1748649600.0\t192.0.2.1\n"
    )
    with pytest.raises(ValueError, match="missing #fields"):
        parse_tsv_log(tsv.splitlines(keepends=True))


def test_ragged_row_raises() -> None:
    """A data row with the wrong token count raises ValueError with line and counts."""
    tsv = (
        "#separator \\x09\n"
        "#fields\tts\tsrc\tdst\n"
        "#types\ttime\tstring\tstring\n"
        "1748649600.0\t192.0.2.1\n"   # only 2 tokens, 3 expected
    )
    with pytest.raises(ValueError) as exc_info:
        parse_tsv_log(tsv.splitlines(keepends=True))
    msg = str(exc_info.value)
    assert "3" in msg   # expected count
    assert "2" in msg   # actual count


def test_bool_unknown_value_raises() -> None:
    """A bool field with a value other than T or F raises ValueError."""
    tsv = (
        "#separator \\x09\n"
        "#fields\tts\tflag\n"
        "#types\ttime\tbool\n"
        "1748649600.0\tyes\n"
    )
    with pytest.raises(ValueError, match="bool"):
        parse_tsv_log(tsv.splitlines(keepends=True))


def test_numeric_empty_field_raises() -> None:
    """An empty token in a count-typed field raises ValueError."""
    tsv = (
        "#separator \\x09\n"
        "#fields\tts\tport\n"
        "#types\ttime\tcount\n"
        "1748649600.0\t(empty)\n"
    )
    with pytest.raises(ValueError, match="empty"):
        parse_tsv_log(tsv.splitlines(keepends=True))


def test_unknown_zeek_type_raises() -> None:
    """An unsupported Zeek type raises ValueError on coercion."""
    tsv = (
        "#separator \\x09\n"
        "#fields\tts\tinfo\n"
        "#types\ttime\trecord\n"
        "1748649600.0\tsomevalue\n"
    )
    with pytest.raises(ValueError, match="unsupported Zeek type"):
        parse_tsv_log(tsv.splitlines(keepends=True))


def test_sink_truncated_final_line_records_file_absolute_lineno() -> None:
    """The bad_lines sink records FILE-ABSOLUTE line numbers: a truncated final
    line (routine mid-write state) is skipped, prior rows parse."""
    tsv = (
        "#separator \\x09\n"
        "#fields\tts\tuid\n"
        "#types\ttime\tstring\n"
        "1748649600.0\tC1\n"
        "1748649601.0\tC2\n"
        "1748649602.0\n"  # truncated: 1 token, 2 expected
    )
    sink: list[tuple[int, str]] = []
    df = parse_tsv_log(tsv.splitlines(keepends=True), bad_lines=sink)
    assert len(df) == 2
    assert df["uid"].tolist() == ["C1", "C2"]
    # 3 header lines + 2 clean data lines put the bad line at file line 6.
    assert sink == [(6, "has 1 fields, expected 2")]


def test_sink_bad_coercion_mid_file_skips_line_and_continues() -> None:
    """A mid-file coercion failure (bool field with an invalid token) skips that
    line into the sink; later lines still parse."""
    tsv = (
        "#separator \\x09\n"
        "#fields\tts\tflag\n"
        "#types\ttime\tbool\n"
        "1748649600.0\tT\n"
        "1748649601.0\tyes\n"  # invalid bool token
        "1748649602.0\tF\n"
    )
    sink: list[tuple[int, str]] = []
    df = parse_tsv_log(tsv.splitlines(keepends=True), bad_lines=sink)
    assert df["ts"].tolist() == [1748649600.0, 1748649602.0]
    assert len(sink) == 1
    assert sink[0][0] == 5
    assert "bool" in sink[0][1]


def test_sink_header_error_still_raises() -> None:
    """Header errors raise even with a sink - a broken header means no row can
    be trusted."""
    tsv = (
        "#separator \\x09\n"
        "#types\ttime\tstring\n"
        "1748649600.0\t192.0.2.1\n"
    )
    sink: list[tuple[int, str]] = []
    with pytest.raises(ValueError, match="missing #fields"):
        parse_tsv_log(tsv.splitlines(keepends=True), bad_lines=sink)


def test_missing_optional_directives_use_zeek_defaults() -> None:
    """Without #set_separator/#empty_field/#unset_field, Zeek spec defaults apply."""
    tsv = (
        "#separator \\x09\n"
        # No #set_separator, #empty_field, or #unset_field
        "#fields\tts\tname\ttags\n"
        "#types\ttime\tstring\tset[string]\n"
        "1748649600.0\t(empty)\talpha,beta\n"   # (empty) → "" for string default
        "1748649601.0\t-\t-\n"                  # - → unset/NaN for string default
    )
    df = parse_tsv_log(tsv.splitlines(keepends=True))
    assert df.iloc[0]["name"] == ""                    # default empty_field applied
    assert df.iloc[0]["tags"] == ["alpha", "beta"]     # default set_separator applied
    assert "name" not in df.iloc[1] or pd.isna(df.iloc[1]["name"])   # default unset


# ── Smoke test ────────────────────────────────────────────────────────────────

def test_conn_tsv_smoke() -> None:
    """Post-normalization smoke: canonical columns, correct dtypes, lists for set/vector."""
    df = _normalize_conn_df(parse_tsv_log(_SMOKE_TSV.splitlines(keepends=True)))

    # Canonical column names present after normalization.
    for col in ("src", "dst", "port", "proto", "ts"):
        assert col in df.columns, f"canonical column {col!r} missing"

    assert len(df) == 2

    # duration dtype is numeric float - not the raw string "-".
    assert df["duration"].dtype == float or str(df["duration"].dtype).startswith("float")
    assert not (df["duration"] == "-").any(), "unset token must not survive as a string"

    # The row with duration=- should be NaN.
    assert df["duration"].isna().any()

    # local_orig values are Python bools, not strings.
    for v in df["local_orig"].dropna():
        assert isinstance(v, (bool,)), f"local_orig should be bool, got {type(v)}"

    # tunnel_parents values are lists, not strings.
    for v in df["tunnel_parents"].dropna():
        assert isinstance(v, list), f"tunnel_parents should be list, got {type(v)}"

    # Unset tunnel_parents row has NaN, not "-".
    assert not (df["tunnel_parents"].dropna() == "-").any()


# ── Zeek syslog.log normalizer + TSV+NDJSON parity ────────────────────────────
#
# v1 promotion of Zeek syslog.log. Normalizer lives in parsers/zeek.py beside
# the conn / dns normalizers; both front-ends produce the Zeek-native
# intermediate frame and the single normalizer maps both to the canonical
# fidelity-aware syslog schema:
#
#   Minimal (both feeds): ts, host, program, raw, message
#   Extended (Zeek only): facility, severity   (uppercase enum strings)
#
# Per-row derivation reuses parsers/syslog.py helpers (strip_header,
# parse_program, normalize_pids, parse_host), so the doubled-timestamp
# invariant - strip_header is ^-anchored - holds on this path.

_SYSLOG_TSV = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tsyslog\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
    "\tproto\tfacility\tseverity\tmessage\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport"
    "\tenum\tstring\tstring\tstring\n"
    # Row A: embedded RFC 3164 hostname present → host = "host1"
    "1779750000.000000\tCSL01\t192.0.2.10\t41514\t198.51.100.20\t514"
    "\tudp\tDAEMON\tINFO"
    "\tJun 11 12:00:00 host1 sshd[1234]: Accepted publickey for user from 192.0.2.10\n"
    # Row B: short body - under 4 whitespace-separated tokens, so parse_host
    # returns "unknown" → fallback to id.orig_h = "192.0.2.10". parse_host is
    # dumb-positional: field 4 verbatim, with NO hostname validation; the
    # fallback is gated on the literal "unknown" sentinel.
    "1779750060.000000\tCSL02\t192.0.2.10\t41515\t198.51.100.20\t514"
    "\tudp\tKERN\tERR"
    "\tkernel: oops\n"
)

# NDJSON equivalent - _path on every line; Zeek native field names.
_SYSLOG_NDJSON = (
    '{"_path":"syslog","ts":1779750000.0,"uid":"CSL01",'
    '"id.orig_h":"192.0.2.10","id.orig_p":41514,'
    '"id.resp_h":"198.51.100.20","id.resp_p":514,"proto":"udp",'
    '"facility":"DAEMON","severity":"INFO",'
    '"message":"Jun 11 12:00:00 host1 sshd[1234]: Accepted publickey for user from 192.0.2.10"}\n'
    '{"_path":"syslog","ts":1779750060.0,"uid":"CSL02",'
    '"id.orig_h":"192.0.2.10","id.orig_p":41515,'
    '"id.resp_h":"198.51.100.20","id.resp_p":514,"proto":"udp",'
    '"facility":"KERN","severity":"ERR",'
    '"message":"kernel: oops"}\n'
)


def test_zeek_syslog_normalizer_tsv_happy_path() -> None:
    """Zeek-syslog TSV → canonical 7-col frame; derived columns correct."""
    from sigwood.parsers.zeek import _normalize_zeek_syslog_df

    raw = parse_tsv_log(_SYSLOG_TSV.splitlines(keepends=True))
    df = _normalize_zeek_syslog_df(raw)

    # Minimal-5-first, then extended.
    assert list(df.columns) == [
        "ts", "host", "program", "raw", "message", "facility", "severity",
    ], "minimal-5 must come first; extended last (concat-friendly)"

    # Dropped Zeek-only columns.
    for col in ("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"):
        assert col not in df.columns

    # Row A: embedded host wins.
    assert df.iloc[0]["host"] == "host1"
    assert df.iloc[0]["program"] == "sshd"
    # `raw` is verbatim from Zeek's message.
    assert df.iloc[0]["raw"].startswith("Jun 11 12:00:00 host1 sshd[1234]:")
    # `message` is header-stripped and PID-normalised.
    assert df.iloc[0]["message"] == "sshd[*]: Accepted publickey for user from 192.0.2.10"
    assert df.iloc[0]["facility"] == "DAEMON"
    assert df.iloc[0]["severity"] == "INFO"
    assert df.iloc[0]["ts"] == 1779750000.0

    # Row B: parse_host returns "unknown" (under-4-field body) → id.orig_h
    # fallback kicks in.
    assert df.iloc[1]["host"] == "192.0.2.10"
    assert df.iloc[1]["program"] == "kernel"
    assert df.iloc[1]["message"] == "kernel: oops"
    assert df.iloc[1]["severity"] == "ERR"


def test_zeek_syslog_tsv_ndjson_parity() -> None:
    """TSV and NDJSON paths produce identical normalized frames."""
    from sigwood.parsers.zeek import _normalize_zeek_syslog_df

    tsv_df    = _normalize_zeek_syslog_df(
        parse_tsv_log(_SYSLOG_TSV.splitlines(keepends=True))
    )
    ndjson_df = _normalize_zeek_syslog_df(_ndjson_df(_SYSLOG_NDJSON))
    _compare(tsv_df, ndjson_df)


def test_zeek_syslog_normalizer_malformed_missing_message_preserves_absence() -> None:
    """Honesty rail: when source `message` is absent, normalizer does NOT
    synthesize message / raw / program just to satisfy shape - the output
    omits those columns so _schema_warning fires with the actionable
    "syslog.log fields not found: …" message. Without this discipline,
    fabricated empty content would flow into the detector/digest."""
    from sigwood.common.loader import _schema_warning
    from sigwood.parsers.zeek import _normalize_zeek_syslog_df

    raw_df = pd.DataFrame([
        {
            "ts": 1779750000.0,
            "uid": "CSL01",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 41514,
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 514,
            "proto": "udp",
            "facility": "DAEMON",
            "severity": "INFO",
            # message intentionally absent
        }
    ])
    df = _normalize_zeek_syslog_df(raw_df)

    # Derived columns absent so the schema warning can fire.
    for col in ("message", "raw", "program"):
        assert col not in df.columns, (
            f"{col} must not be synthesized when source `message` is missing"
        )
    # ts / facility / severity survive (carried, not derived).
    assert "ts" in df.columns
    assert "facility" in df.columns
    assert "severity" in df.columns

    warning = _schema_warning("syslog*.log*", df)
    assert warning is not None
    assert "syslog.log fields not found" in warning
    assert "message" in warning
    assert "program" in warning
    assert "raw" in warning


def test_zeek_tsv_sniff_syslog_path_claims_syslog() -> None:
    """TSV sniff layer claims `#path syslog` - the TSV twin of the NDJSON
    `_path == "syslog"` claim. Test in test_sniff_recognizers covers the
    NDJSON side."""
    from sigwood.parsers.zeek_tsv import sniff

    sample = [
        "#separator \\x09\n",
        "#set_separator\t,\n",
        "#empty_field\t(empty)\n",
        "#unset_field\t-\n",
        "#path\tsyslog\n",
        "#fields\tts\tuid\tid.orig_h\tfacility\tseverity\tmessage\n",
        "#types\ttime\tstring\taddr\tstring\tstring\tstring\n",
    ]
    assert sniff(sample) == "syslog"


def test_zeek_syslog_normalizer_strips_trailing_crlf_from_raw() -> None:
    """Zeek's NDJSON `message` field can
    carry the upstream record's trailing CR/LF. It must not leak into
    canonical `raw`, or the syslog detector's `title=str(row.raw)[:180]`
    would render a blank spacer row beneath every affected finding. Fix is a
    narrow trailing-line-terminator strip at the parser seam (mirrors flat
    `load_syslog`'s `line.rstrip("\\n")` discipline). RFC 5737 placeholders.

    Canonical `message` was already clean because `strip_header` calls
    `.strip()`; this test pins both columns to the same contract.
    """
    from sigwood.parsers.zeek import _normalize_zeek_syslog_df

    raw_df = pd.DataFrame([
        {
            "ts":         1779750000.0,
            "uid":        "CSL01",
            "id.orig_h":  "192.0.2.10",
            "id.orig_p":  41514,
            "id.resp_h":  "198.51.100.20",
            "id.resp_p":  514,
            "proto":      "udp",
            "facility":   "DAEMON",
            "severity":   "INFO",
            # Trailing LF, mixed-form CR/LF, bare CR - any combination
            # that an upstream agent might leave on the wire.
            "message": "Jun 11 12:00:00 host1 sshd[1234]: line ending in LF\n",
        },
        {
            "ts":         1779750060.0,
            "uid":        "CSL02",
            "id.orig_h":  "192.0.2.10",
            "id.orig_p":  41515,
            "id.resp_h":  "198.51.100.20",
            "id.resp_p":  514,
            "proto":      "udp",
            "facility":   "DAEMON",
            "severity":   "INFO",
            "message": "Jun 11 12:01:00 host1 sshd[1235]: line ending in CRLF\r\n",
        },
        {
            "ts":         1779750120.0,
            "uid":        "CSL03",
            "id.orig_h":  "192.0.2.10",
            "id.orig_p":  41516,
            "id.resp_h":  "198.51.100.20",
            "id.resp_p":  514,
            "proto":      "udp",
            "facility":   "DAEMON",
            "severity":   "INFO",
            "message": "Jun 11 12:02:00 host1 sshd[1236]: line ending in bare CR\r",
        },
    ])
    df = _normalize_zeek_syslog_df(raw_df)

    # Canonical raw must not carry trailing CR or LF on any row.
    for value in df["raw"].tolist():
        assert not value.endswith("\n"), f"raw must not end in LF: {value!r}"
        assert not value.endswith("\r"), f"raw must not end in CR: {value!r}"
    # Canonical message remains clean too (already guaranteed by strip_header).
    for value in df["message"].tolist():
        assert not value.endswith("\n"), f"message must not end in LF: {value!r}"
        assert not value.endswith("\r"), f"message must not end in CR: {value!r}"

    # Detector title contract: str(raw)[:180] must be a single physical line.
    for value in df["raw"].tolist():
        title = str(value)[:180]
        assert "\n" not in title, (
            f"detector title (str(raw)[:180]) must not contain a newline; "
            f"got: {title!r}"
        )

    # The raw payload up to the terminator stays intact (no broader trim).
    assert df.iloc[0]["raw"].endswith("line ending in LF")
    assert df.iloc[1]["raw"].endswith("line ending in CRLF")
    assert df.iloc[2]["raw"].endswith("line ending in bare CR")
