"""Unit tests for per-parser sniff recognizers (pure, no I/O).

All sample data is synthetic per the privacy rail - RFC 5737 documentation
IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) and placeholder hostnames only.
"""

from __future__ import annotations

import pytest

from sigwood.parsers import cloudtrail, dnsmasq, syslog, zeek, zeek_tsv


# ── Sample fixtures ───────────────────────────────────────────────────────────

ZEEK_TSV_CONN_SAMPLE: list[str] = [
    "#separator \\x09\n",
    "#set_separator\t,\n",
    "#empty_field\t(empty)\n",
    "#unset_field\t-\n",
    "#path\tconn\n",
    "#open\t2026-06-01-12-00-00\n",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\n",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\n",
]

ZEEK_TSV_DNS_SAMPLE: list[str] = [
    "#separator \\x09\n",
    "#set_separator\t,\n",
    "#empty_field\t(empty)\n",
    "#unset_field\t-\n",
    "#path\tdns\n",
    "#open\t2026-06-01-12-00-00\n",
    "#fields\tts\tuid\tid.orig_h\tquery\tqtype\n",
    "#types\ttime\tstring\taddr\tstring\tcount\n",
]

ZEEK_TSV_UNSUPPORTED_PATH_SAMPLE: list[str] = [
    "#separator \\x09\n",
    "#set_separator\t,\n",
    "#empty_field\t(empty)\n",
    "#unset_field\t-\n",
    "#path\thttp\n",
    "#fields\tts\tuid\thost\n",
    "#types\ttime\tstring\tstring\n",
]

ZEEK_NDJSON_CONN_SAMPLE: list[str] = [
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",'
    ' "id.resp_p": 443, "proto": "tcp", "duration": 1.23}\n',
]

ZEEK_NDJSON_CONN_NO_DURATION_SAMPLE: list[str] = [
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",'
    ' "id.resp_p": 443, "proto": "tcp"}\n',
]

ZEEK_NDJSON_DNS_SAMPLE: list[str] = [
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "query": "example.test", "qtype": 1}\n',
]

# Zeek-native conn line with the _path directive - must claim "conn" via the
# _path gate (layer 1), even before the field-set fallback would fire.
ZEEK_NDJSON_CONN_WITH_PATH_SAMPLE: list[str] = [
    '{"_path": "conn", "ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
    ' "duration": 1.23}\n',
]

# Zeek-native dns line with the _path directive - must claim "dns" via the
# _path gate.
ZEEK_NDJSON_DNS_WITH_PATH_SAMPLE: list[str] = [
    '{"_path": "dns", "ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "query": "example.test", "qtype": 1}\n',
]

# Zeek's own non-conn / non-dns NDJSON logs - they carry the 5-tuple as
# connection context but are NOT conn frames. The _path gate rejects them
# so the sniff cascade falls through to the blob floor.
ZEEK_NDJSON_NOTICE_SAMPLE: list[str] = [
    '{"_path": "notice", "ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
    ' "note": "Placeholder::Note", "msg": "placeholder message"}\n',
]

ZEEK_NDJSON_SYSLOG_SAMPLE: list[str] = [
    '{"_path": "syslog", "ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 514, "proto": "udp",'
    ' "facility": "LOCAL0", "severity": "INFO",'
    ' "message": "placeholder message"}\n',
]

# Zeek NDJSON syslog WITHOUT the _path directive. Some upstream agents emit
# Zeek logs minus _path. Without a syslog field-set fallback such a line would
# fall through the _path gate and the conn field-set fallback would claim it as
# conn (5-tuple present, no `query`), leaving operators an empty frame from
# `sigwood syslog`. The syslog field-set fallback (facility + severity +
# message + ts + src) catches it BEFORE the conn fallback. RFC 5737 placeholders only.
ZEEK_NDJSON_SYSLOG_NO_PATH_SAMPLE: list[str] = [
    '{"ts": 1779750000.0, "uid": "CSL01",'
    ' "id.orig_h": "192.0.2.10", "id.orig_p": 41514,'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 514,'
    ' "proto": "udp", "facility": "DAEMON", "severity": "INFO",'
    ' "message": "Jun 11 12:00:00 host1 sshd[1234]: placeholder"}\n',
]

# Defensive negatives - a line missing ONE of (facility, severity, message)
# must NOT be claimed as syslog. With the full 5-tuple still present, the
# conn fallback claims them as conn (the documented field-set behaviour for
# hand-rolled NDJSON). These prove the syslog fallback is tight on the
# three-key signature, not a "has facility OR severity" loosening.
ZEEK_NDJSON_NO_PATH_CONN_NO_FACILITY_SAMPLE: list[str] = [
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
    ' "severity": "INFO", "message": "placeholder"}\n',
]
ZEEK_NDJSON_NO_PATH_CONN_NO_SEVERITY_SAMPLE: list[str] = [
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
    ' "facility": "DAEMON", "message": "placeholder"}\n',
]
ZEEK_NDJSON_NO_PATH_CONN_NO_MESSAGE_SAMPLE: list[str] = [
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
    ' "facility": "DAEMON", "severity": "INFO"}\n',
]

ZEEK_NDJSON_ANALYZER_SAMPLE: list[str] = [
    '{"_path": "analyzer", "ts": 1779750000.0, "cause": "violation",'
    ' "analyzer_kind": "protocol", "analyzer_name": "Placeholder",'
    ' "uid": "Cxxxxxx", "id.orig_h": "192.0.2.10",'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
    ' "failure_reason": "placeholder"}\n',
]

# notice.log-shaped NDJSON WITHOUT _path. Carries the conn 5-tuple via
# id.* keys (so a field-set conn fallback would claim it) AND its
# OWN native `src`/`dst` columns. That double-presence is the
# rename-collision signal: the loader's id.orig_h→src rename would
# duplicate the canonical `src` column and crash the conn summariser
# with pandas' "Grouper for 'src' not 1-dimensional". The field-set
# fallback must reject this and fall through to None so the sniff
# cascade lands at the blob floor.
ZEEK_NDJSON_NOTICE_NO_PATH_SAMPLE: list[str] = [
    '{"ts": 1779750000.0, "uid": "Cxxxxxx",'
    ' "id.orig_h": "192.0.2.10", "id.orig_p": 41514,'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
    ' "src": "192.0.2.10", "dst": "198.51.100.20",'
    ' "note": "Placeholder::Note", "msg": "placeholder message"}\n',
]

# Hand-rolled dns-shaped NDJSON carrying BOTH `id.orig_h` and a native
# `src`. The rename pair (id.orig_h → src) collides, so the 2a dns
# fallback must reject the claim and fall through to None.
ZEEK_NDJSON_DNS_NO_PATH_NATIVE_SRC_COLLISION_SAMPLE: list[str] = [
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "src": "192.0.2.10", "query": "example.test", "qtype": 1}\n',
]

CLOUDTRAIL_NDJSON_SAMPLE: list[str] = [
    '{"eventVersion": "1.08", "eventTime": "2026-06-01T12:00:00Z",'
    ' "userIdentity": {"type": "IAMUser"}, "eventName": "GetObject",'
    ' "eventSource": "s3.amazonaws.com"}\n',
]

CLOUDTRAIL_ENVELOPE_SAMPLE: list[str] = [
    "{\n",
    '  "Records": [\n',
    "    {\n",
    '      "eventVersion": "1.08",\n',
    '      "eventTime": "2026-06-01T12:00:00Z",\n',
    '      "userIdentity": {\n',
    '        "type": "IAMUser"\n',
    "      },\n",
    '      "eventName": "GetObject"\n',
    "    }\n",
    "  ]\n",
    "}\n",
]

# Envelope whose first record is enormous - used to verify the structural
# scan does not depend on the sample being fully parseable as JSON. Mimics a
# pretty-printed event with many extra keys before the recognizer's tokens.
CLOUDTRAIL_ENVELOPE_BIG_RECORD_SAMPLE: list[str] = (
    ["{\n", '  "Records": [\n', "    {\n"]
    + [f'      "extraKey{i}": "value{i}",\n' for i in range(120)]
    + [
        '      "eventVersion": "1.08",\n',
        '      "eventTime": "2026-06-01T12:00:00Z",\n',
        '      "userIdentity": {"type": "IAMUser"}\n',
    ]
)

DNSMASQ_DNS_SAMPLE: list[str] = [
    "Jun  1 12:00:00 piholehost dnsmasq[123]: query[A] example.test from 192.0.2.10\n",
    "Jun  1 12:00:01 piholehost dnsmasq[123]: forwarded example.test to 198.51.100.53\n",
]

# All-DHCP sample: outer grammar matches but inner is dhcp only - must NOT
# claim "dns". Guards this distinction.
DNSMASQ_DHCP_ONLY_SAMPLE: list[str] = [
    "Jun  1 12:00:00 piholehost dnsmasq[123]: DHCP 192.0.2.10 is placeholder-host\n",
    "Jun  1 12:00:01 piholehost dnsmasq[123]: DHCP placeholder-host is 192.0.2.11\n",
]

# All-unknown sample: outer grammar matches but message is unrecognized
# chatter - must NOT claim "dns".
DNSMASQ_UNKNOWN_ONLY_SAMPLE: list[str] = [
    "Jun  1 12:00:00 piholehost dnsmasq[123]: started, version 2.86 cachesize 10000\n",
    "Jun  1 12:00:01 piholehost dnsmasq[123]: compile time options: IPv6 GNU-getopt\n",
]

# DHCP prefix followed by a real DNS event - must still claim "dns" (the
# budget tolerates leading DHCP/unknown lines).
DNSMASQ_DHCP_PREFIX_THEN_DNS_SAMPLE: list[str] = [
    "Jun  1 12:00:00 piholehost dnsmasq[123]: DHCP 192.0.2.10 is placeholder-host\n",
    "Jun  1 12:00:01 piholehost dnsmasq[123]: query[A] example.test from 192.0.2.11\n",
]

SYSLOG_SAMPLE: list[str] = [
    "<13>Jun  1 12:00:00 examplehost sshd[1234]: Accepted publickey for placeholder\n",
    "Jun  1 12:00:01 examplehost cron[5678]: (root) CMD (placeholder)\n",
]

SYSLOG_NO_PRI_SAMPLE: list[str] = [
    "Jun  1 12:00:00 examplehost sshd[1234]: Accepted publickey for placeholder\n",
]

GARBAGE_TEXT_SAMPLE: list[str] = [
    "hello world\n",
    "this is not a log\n",
    "lorem ipsum dolor sit amet\n",
]

# Generic JSON envelope with a "Records" key but no CloudTrail event keys
# - must NOT be claimed as cloudtrail. Guards the structural scan's
# precision.
GENERIC_RECORDS_JSON_SAMPLE: list[str] = [
    "{\n",
    '  "Records": [\n',
    "    {\n",
    '      "foo": "bar",\n',
    '      "baz": 42\n',
    "    }\n",
    "  ]\n",
    "}\n",
]

EMPTY_SAMPLE: list[str] = []

BLANK_SAMPLE: list[str] = ["\n", "\n", "  \n"]


# ── Positive recognizer tests ─────────────────────────────────────────────────

def test_zeek_tsv_sniff_conn() -> None:
    assert zeek_tsv.sniff(ZEEK_TSV_CONN_SAMPLE) == "conn"


def test_zeek_tsv_sniff_dns() -> None:
    assert zeek_tsv.sniff(ZEEK_TSV_DNS_SAMPLE) == "dns"


def test_zeek_tsv_sniff_unsupported_path_returns_none() -> None:
    # #path http has no digester in v1 - must fall through, not claim a slot.
    assert zeek_tsv.sniff(ZEEK_TSV_UNSUPPORTED_PATH_SAMPLE) is None


def test_zeek_tsv_sniff_missing_fields_directive_returns_none() -> None:
    sample = [
        "#separator \\x09\n",
        "#path\tconn\n",
    ]
    assert zeek_tsv.sniff(sample) is None


def test_zeek_tsv_sniff_missing_separator_returns_none() -> None:
    sample = [
        "#path\tconn\n",
        "#fields\tts\tuid\n",
    ]
    # Without #separator we cannot reliably split other directives.
    assert zeek_tsv.sniff(sample) is None


def test_zeek_tsv_sniff_path_substring_in_payload_returns_none() -> None:
    # literal-substring "#path" in arbitrary text must NOT
    # claim Zeek TSV. The leading-#-required guard handles this.
    sample = [
        "this line mentions #path conn but is not a header\n",
        "second line of prose\n",
    ]
    assert zeek_tsv.sniff(sample) is None


def test_zeek_sniff_conn_ndjson() -> None:
    assert zeek.sniff(ZEEK_NDJSON_CONN_SAMPLE) == "conn"


def test_zeek_sniff_conn_no_duration() -> None:
    # duration is optional (Zeek omits it on open connections).
    assert zeek.sniff(ZEEK_NDJSON_CONN_NO_DURATION_SAMPLE) == "conn"


def test_zeek_sniff_dns_ndjson() -> None:
    assert zeek.sniff(ZEEK_NDJSON_DNS_SAMPLE) == "dns"


def test_zeek_sniff_dns_wins_over_conn_when_query_present() -> None:
    line = (
        '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",'
        ' "id.resp_p": 443, "proto": "tcp", "duration": 0.1, "query": "example.test"}\n'
    )
    # Pathological mix: should classify as dns because query is the
    # documented disambiguator.
    assert zeek.sniff([line]) == "dns"


# ── _path gate - Zeek-native conn/dns NDJSON ──────────────────────────────────


def test_zeek_sniff_conn_with_path_directive() -> None:
    """_path == 'conn' claims conn directly (layer 1)."""
    assert zeek.sniff(ZEEK_NDJSON_CONN_WITH_PATH_SAMPLE) == "conn"


def test_zeek_sniff_dns_with_path_directive() -> None:
    """_path == 'dns' claims dns directly (layer 1)."""
    assert zeek.sniff(ZEEK_NDJSON_DNS_WITH_PATH_SAMPLE) == "dns"


# ── _path gate - Zeek non-conn/non-dns logs are handled correctly ────────────
#
# Zeek's own syslog.log, notice.log, analyzer.log lines carry the 5-tuple as
# connection context. Without the _path gate, the field-set fallback would claim them as
# conn, the loader would normalise them, and the digest summariser would
# crash on the resulting frame (e.g. duplicate `src` column → "Grouper for
# 'src' not 1-dimensional"). The _path gate is authoritative:
# _path == "syslog" is a real claim (v1 promotion); _path in {notice,
# analyzer, …} still falls to the blob floor.


def test_zeek_sniff_notice_path_not_claimed_as_conn() -> None:
    assert zeek.sniff(ZEEK_NDJSON_NOTICE_SAMPLE) is None


def test_zeek_sniff_syslog_path_claims_syslog() -> None:
    # _path == "syslog" → the new v1 syslog claim (fidelity-aware syslog
    # schema). Pre-promotion this returned None; post-promotion this is the
    # entry point that routes Zeek syslog.log through _normalize_zeek_syslog_df.
    assert zeek.sniff(ZEEK_NDJSON_SYSLOG_SAMPLE) == "syslog"


def test_zeek_sniff_analyzer_path_not_claimed_as_conn() -> None:
    assert zeek.sniff(ZEEK_NDJSON_ANALYZER_SAMPLE) is None


# ── Field-set fallback - Zeek NDJSON without _path ───────────────────────────
#
# Some upstream agents emit Zeek logs minus the _path directive. The original
# v1 promotion only claimed syslog via the _path gate, so a no-_path Zeek
# syslog.log fell through to the conn fallback (full 5-tuple present, no
# `query`) and was misrouted as conn. The syslog field-set fallback now
# catches these BEFORE the conn fallback, gated on the tight (facility,
# severity, message) triple that no other Zeek log type carries.


def test_zeek_sniff_syslog_without_path_claims_syslog() -> None:
    """Zeek syslog NDJSON without _path is claimed via the field-set fallback
    on (facility, severity, message) + src/ts; without it this would fall to conn."""
    assert zeek.sniff(ZEEK_NDJSON_SYSLOG_NO_PATH_SAMPLE) == "syslog"


def test_zeek_sniff_field_set_syslog_requires_facility() -> None:
    """Negative: missing `facility` falls through the syslog fallback. Full
    5-tuple still present → claimed as conn by the conn fallback."""
    assert zeek.sniff(ZEEK_NDJSON_NO_PATH_CONN_NO_FACILITY_SAMPLE) == "conn"


def test_zeek_sniff_field_set_syslog_requires_severity() -> None:
    """Negative: missing `severity` falls through the syslog fallback."""
    assert zeek.sniff(ZEEK_NDJSON_NO_PATH_CONN_NO_SEVERITY_SAMPLE) == "conn"


def test_zeek_sniff_field_set_syslog_requires_message() -> None:
    """Negative: missing `message` falls through the syslog fallback. The
    triple is critical - loosening any of facility/severity/message would
    reopen the notice/analyzer false-claim risk."""
    assert zeek.sniff(ZEEK_NDJSON_NO_PATH_CONN_NO_MESSAGE_SAMPLE) == "conn"


# ── Field-set fallback - rename-collision guard ──────────────────────────────
#
# Records carrying BOTH a Zeek-native key (id.orig_h/id.resp_h/id.resp_p/
# orig_bytes/TTLs/answers/TC) AND its canonical rename target are NOT
# clean conn/dns frames - the loader's rename would crash the summariser.
# The field-set fallback must reject them; sniff returns None and the
# orchestrator drops to the blob floor.


def test_zeek_sniff_notice_no_path_native_src_collision_returns_none() -> None:
    """notice.log-shaped NDJSON without _path carrying id.orig_h plus
    native src/dst must NOT be claimed as conn. Falls through to None so the
    orchestrator drops to blob."""
    assert zeek.sniff(ZEEK_NDJSON_NOTICE_NO_PATH_SAMPLE) is None


def test_zeek_sniff_dns_no_path_native_src_collision_returns_none() -> None:
    """A dns-shaped pathless NDJSON carrying both id.orig_h AND native src
    is also a rename-collision shape - the 2a dns fallback must reject
    it."""
    assert zeek.sniff(ZEEK_NDJSON_DNS_NO_PATH_NATIVE_SRC_COLLISION_SAMPLE) is None


def test_zeek_sniff_clean_no_path_conn_still_claims_conn() -> None:
    """Regression: a clean pathless conn NDJSON (id.* keys only, NO
    native src/dst) must STILL claim conn. Over-rejection would break
    legitimate exported Zeek conn NDJSON."""
    assert zeek.sniff(ZEEK_NDJSON_CONN_SAMPLE) == "conn"


def test_zeek_sniff_clean_no_path_dns_still_claims_dns() -> None:
    """Regression: a clean pathless dns NDJSON (id.orig_h + query, NO
    native src) must STILL claim dns."""
    assert zeek.sniff(ZEEK_NDJSON_DNS_SAMPLE) == "dns"


def test_zeek_sniff_path_gate_trusted_over_field_set() -> None:
    """When _path is present, it is the only signal consulted - the field set
    (even a valid conn or dns set) does not get a second say. This is the
    contract that prevents notice/syslog/analyzer false claims."""
    # _path says "weird"; field set looks like conn. _path wins → None.
    line = (
        '{"_path": "weird", "ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
        ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp"}\n'
    )
    assert zeek.sniff([line]) is None


def test_cloudtrail_sniff_ndjson() -> None:
    assert cloudtrail.sniff(CLOUDTRAIL_NDJSON_SAMPLE) == "cloudtrail"


def test_cloudtrail_sniff_envelope() -> None:
    assert cloudtrail.sniff(CLOUDTRAIL_ENVELOPE_SAMPLE) == "cloudtrail"


def test_cloudtrail_sniff_envelope_with_huge_first_record() -> None:
    # The structural scan finds quoted keys without needing a parseable
    # bounded sample - even when the first record sprawls.
    assert cloudtrail.sniff(CLOUDTRAIL_ENVELOPE_BIG_RECORD_SAMPLE) == "cloudtrail"


def test_cloudtrail_sniff_generic_records_returns_none() -> None:
    # a "Records" key without CT-event keys must
    # NOT claim cloudtrail.
    assert cloudtrail.sniff(GENERIC_RECORDS_JSON_SAMPLE) is None


def test_cloudtrail_sniff_event_keys_as_string_values_does_not_false_positive() -> None:
    # The quoted-key + colon regex requires the token to appear as a JSON
    # key, not as a value.
    sample = [
        '{"message": "the eventTime field was updated"}\n',
        '{"note": "userIdentity values include IAMUser"}\n',
    ]
    assert cloudtrail.sniff(sample) is None


def test_dnsmasq_sniff_dns() -> None:
    assert dnsmasq.sniff(DNSMASQ_DNS_SAMPLE) == "dns"


def test_dnsmasq_sniff_dhcp_only_returns_none() -> None:
    assert dnsmasq.sniff(DNSMASQ_DHCP_ONLY_SAMPLE) is None


def test_dnsmasq_sniff_unknown_only_returns_none() -> None:
    assert dnsmasq.sniff(DNSMASQ_UNKNOWN_ONLY_SAMPLE) is None


def test_dnsmasq_sniff_tolerates_dhcp_prefix_before_dns_event() -> None:
    assert dnsmasq.sniff(DNSMASQ_DHCP_PREFIX_THEN_DNS_SAMPLE) == "dns"


def test_syslog_sniff_with_pri() -> None:
    assert syslog.sniff(SYSLOG_SAMPLE) == "syslog"


def test_syslog_sniff_without_pri() -> None:
    assert syslog.sniff(SYSLOG_NO_PRI_SAMPLE) == "syslog"


def test_syslog_sniff_garbage_text_returns_none() -> None:
    # The original parse_line-non-None contract would have classified this
    # as syslog; the tightened recognizer correctly returns None.
    assert syslog.sniff(GARBAGE_TEXT_SAMPLE) is None


def test_syslog_sniff_missing_timestamp_returns_none() -> None:
    # Looks vaguely header-shaped but timestamp does not parse.
    sample = ["Foo  1 12:00:00 examplehost prog: text\n"]
    assert syslog.sniff(sample) is None


# ── Edge cases shared by all recognizers ──────────────────────────────────────

@pytest.mark.parametrize(
    "mod",
    [zeek_tsv, zeek, cloudtrail, dnsmasq, syslog],
    ids=["zeek_tsv", "zeek", "cloudtrail", "dnsmasq", "syslog"],
)
def test_empty_sample_returns_none(mod) -> None:
    assert mod.sniff(EMPTY_SAMPLE) is None


@pytest.mark.parametrize(
    "mod",
    [zeek_tsv, zeek, cloudtrail, dnsmasq, syslog],
    ids=["zeek_tsv", "zeek", "cloudtrail", "dnsmasq", "syslog"],
)
def test_blank_sample_returns_none(mod) -> None:
    assert mod.sniff(BLANK_SAMPLE) is None


@pytest.mark.parametrize(
    "mod",
    [zeek_tsv, zeek, cloudtrail, dnsmasq, syslog],
    ids=["zeek_tsv", "zeek", "cloudtrail", "dnsmasq", "syslog"],
)
def test_garbage_text_returns_none(mod) -> None:
    assert mod.sniff(GARBAGE_TEXT_SAMPLE) is None


# ── Cross-format negative matrix ──────────────────────────────────────────────
#
# Each recognizer fed with every OTHER format's sample. Most pairs return
# None. The one documented overlap is syslog.sniff(dnsmasq sample) - dnsmasq
# IS RFC 3164, so the recognizer-level signal is genuinely "syslog"; the
# orchestrator resolves the ambiguity by running dnsmasq first.

_FOREIGN_SAMPLES = {
    "zeek_tsv_conn":   (zeek_tsv, ZEEK_TSV_CONN_SAMPLE),
    "zeek_tsv_dns":    (zeek_tsv, ZEEK_TSV_DNS_SAMPLE),
    "zeek_ndjson_conn": (zeek, ZEEK_NDJSON_CONN_SAMPLE),
    "zeek_ndjson_dns": (zeek, ZEEK_NDJSON_DNS_SAMPLE),
    "ct_ndjson":       (cloudtrail, CLOUDTRAIL_NDJSON_SAMPLE),
    "ct_envelope":     (cloudtrail, CLOUDTRAIL_ENVELOPE_SAMPLE),
    "dnsmasq":         (dnsmasq, DNSMASQ_DNS_SAMPLE),
    "syslog":          (syslog, SYSLOG_SAMPLE),
}


@pytest.mark.parametrize("origin_name", list(_FOREIGN_SAMPLES.keys()))
@pytest.mark.parametrize(
    "target_mod",
    [zeek_tsv, zeek, cloudtrail, dnsmasq, syslog],
    ids=["zeek_tsv", "zeek", "cloudtrail", "dnsmasq", "syslog"],
)
def test_cross_format_negative_matrix(origin_name, target_mod) -> None:
    origin_mod, sample = _FOREIGN_SAMPLES[origin_name]
    if target_mod is origin_mod:
        pytest.skip("self-match handled by positive tests")
    result = target_mod.sniff(sample)
    # Documented overlap: dnsmasq logs ARE syslog. The orchestrator's
    # precedence (dnsmasq before syslog) is what resolves this.
    if target_mod is syslog and origin_name == "dnsmasq":
        assert result == "syslog"
    else:
        assert result is None, (
            f"{target_mod.__name__}.sniff falsely claimed {result!r} for "
            f"a {origin_name} sample"
        )
