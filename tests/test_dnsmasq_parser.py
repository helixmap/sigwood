"""Tests for the dnsmasq/Pi-hole parser (parsers/dnsmasq.py).

All IP addresses use RFC 5737 documentation space: 192.0.2.x, 198.51.100.x.
All domain names use .test or .invalid placeholder TLDs.
"""

from __future__ import annotations

from datetime import timedelta, timezone
from datetime import datetime

import pytest

from sigwood.common.loader.types import _PIHOLE_COLUMNS
from sigwood.parsers.dnsmasq import parse_line, sniff
from sigwood.runner import _DNS_PIHOLE_EMPTY_COLUMNS


# ── Fixture helpers ───────────────────────────────────────────────────────────

def _line(message: str) -> str:
    """Wrap a dnsmasq inner message in a valid outer header."""
    return f"Jun  1 12:00:00 dnsmasq[623]: {message}"


def _line_with_host(message: str) -> str:
    """Wrap a dnsmasq inner message in a valid syslog header with a hostname."""
    return f"Jun  1 12:00:00 resolver-host dnsmasq[623]: {message}"


# ── Event-type parsing ────────────────────────────────────────────────────────

def test_parse_query_line() -> None:
    raw = _line("query[A] example.test from 192.0.2.1")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "query"
    assert result["qtype"] == "A"
    assert result["query"] == "example.test"
    assert result["src"] == "192.0.2.1"


def test_parse_query_line_with_syslog_hostname() -> None:
    raw = _line_with_host("query[A] example.test from 192.0.2.1")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "query"
    assert result["query"] == "example.test"
    assert result["src"] == "192.0.2.1"


def test_parse_forwarded_line() -> None:
    raw = _line("forwarded example.test to 198.51.100.53")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "forwarded"
    assert result["query"] == "example.test"
    assert result["src"] is None


def test_parse_reply_line() -> None:
    raw = _line("reply example.test is 203.0.113.1")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "reply"
    assert result["query"] == "example.test"


def test_parse_cached_line() -> None:
    raw = _line("cached example.test is 203.0.113.1")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "cached"
    assert result["query"] == "example.test"


def test_parse_cached_stale_line() -> None:
    """cached-stale maps to event_type 'cached', not 'cached-stale'."""
    raw = _line("cached-stale example.test is 203.0.113.1")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "cached"
    assert result["query"] == "example.test"


def test_parse_gravity_blocked_address() -> None:
    raw = _line("gravity blocked bad.example.test is 0.0.0.0")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "gravity_blocked"
    assert result["query"] == "bad.example.test"


def test_parse_gravity_blocked_nodata() -> None:
    """NODATA form retains the gravity-blocked grammar verdict."""
    raw = _line("gravity blocked bad.example.test is NODATA")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "gravity_blocked"


def test_parse_gravity_blocked_cname_address() -> None:
    raw = _line("gravity blocked (CNAME) alias.example.test is 0.0.0.0")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "gravity_blocked"
    assert result["query"] == "alias.example.test"


def test_parse_gravity_blocked_cname_nodata() -> None:
    raw = _line("gravity blocked (CNAME) alias.example.test is NODATA")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "gravity_blocked"
    assert result["query"] == "alias.example.test"


def test_parse_gravity_blocked_ipv6_zero() -> None:
    """:: (IPv6 null) is still classified as a gravity block."""
    raw = _line("gravity blocked bad.example.test is ::")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "gravity_blocked"


def test_parse_config_slash_form() -> None:
    """/etc/hosts source form → event_type 'config'."""
    raw = _line("/etc/hosts example.test is 192.0.2.10")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "config"
    assert result["query"] == "example.test"


def test_parse_config_slash_form_with_syslog_hostname() -> None:
    raw = _line_with_host("/etc/hosts example.test is 192.0.2.10")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "config"
    assert result["query"] == "example.test"


def test_parse_config_keyword_form() -> None:
    """'config' keyword source form → event_type 'config'."""
    raw = _line("config example.test is NODATA")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "config"
    assert result["query"] == "example.test"


def test_parse_validation_line() -> None:
    raw = _line("validation result is SECURE")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "validation"
    assert result["query"] is None


def test_parse_unknown_passthrough() -> None:
    """Unrecognized inner message remains an unknown count-bearing row."""
    raw = _line("something totally unrecognized xyz-12345")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "unknown"
    assert result["query"] is None


# ── Outer-grammar failures and null inputs ────────────────────────────────────

def test_parse_outer_fail_returns_none() -> None:
    assert parse_line("not a valid dnsmasq line at all") is None


def test_parse_blank_returns_none() -> None:
    assert parse_line("") is None


def test_parse_comment_returns_none() -> None:
    assert parse_line("# this is a comment") is None


# ── Timestamp behaviour ───────────────────────────────────────────────────────

def test_timestamp_utc_aware() -> None:
    """Parsed timestamp carries tzinfo=timezone.utc."""
    raw = _line("query[A] example.test from 192.0.2.1")
    result = parse_line(raw)
    assert result is not None
    assert result["ts"] is not None
    assert result["ts"].tzinfo == timezone.utc


def test_timestamp_year_rollback() -> None:
    """A timestamp more than 7 days in the future is rolled back to the prior year."""
    future = (
        __import__("datetime").datetime.now(timezone.utc) + timedelta(days=10)
    ).replace(hour=12, minute=0, second=0, microsecond=0)
    raw = f"{future.strftime('%b')} {future.day:2d} 12:00:00 dnsmasq[1]: query[A] x.test from 192.0.2.1"
    result = parse_line(raw)
    assert result is not None
    ts = result["ts"]
    assert ts is not None
    assert ts == future.replace(year=future.year - 1)


def test_timestamp_host_local_epoch(pin_tz) -> None:
    """The wall-clock is interpreted host-local: row ts carries the true epoch.

    The expected epoch is manual fixed-offset arithmetic (+6h for Etc/GMT+6),
    never parse_timestamp - the expectation must not share the code under test.
    """
    pin_tz("Etc/GMT+6")
    local_naive = (datetime.now() - timedelta(days=30)).replace(
        second=0, microsecond=0
    )
    stamp = (
        f"{local_naive.strftime('%b')} {local_naive.day:2d} "
        f"{local_naive.strftime('%H:%M:%S')}"
    )
    raw = f"{stamp} dnsmasq[623]: query[A] example.test from 192.0.2.1"
    result = parse_line(raw)
    assert result is not None
    assert result["ts"] is not None
    expected = (local_naive + timedelta(hours=6)).replace(tzinfo=timezone.utc)
    assert result["ts"].timestamp() == expected.timestamp()


# ── Schema contract ───────────────────────────────────────────────────────────

def test_canonical_key_is_query_not_domain() -> None:
    """The emitted dict uses 'query' as the key, never 'domain'."""
    raw = _line("query[A] example.test from 192.0.2.1")
    result = parse_line(raw)
    assert result is not None
    assert "query" in result
    assert "domain" not in result


def test_host_is_empty_string() -> None:
    """Parser leaves host as '' - the loader fills it from the filename stem."""
    raw = _line("query[A] example.test from 192.0.2.1")
    result = parse_line(raw)
    assert result is not None
    assert result["host"] == ""


def test_all_keys_present_on_every_non_none_result() -> None:
    """Every non-None result has the full canonical key set."""
    expected_keys = {
        "ts", "src", "query", "event_type", "qtype",
        "host",
    }
    lines = [
        _line("query[A] example.test from 192.0.2.1"),
        _line("forwarded example.test to 198.51.100.53"),
        _line("reply example.test is 203.0.113.1"),
        _line("cached example.test is 203.0.113.1"),
        _line("gravity blocked bad.example.test is 0.0.0.0"),
        _line("/etc/hosts example.test is 192.0.2.10"),
        _line("validation result is SECURE"),
        _line("dnssec-query[DS] example.test to 198.51.100.53"),  # dnssec_query
        _line("special domain example.test is 192.0.2.10"),        # special
        _line("DHCP 192.0.2.50 is myhost.test"),                        # dhcp
        _line("Pi-hole hostname pihole.test is 192.0.2.1"),            # pihole_hostname
        _line("regex denied telemetry.example.test is 0.0.0.0"),     # regex_blocked
        _line("something totally unrecognized xyz-12345"),            # unknown
    ]
    for raw in lines:
        result = parse_line(raw)
        assert result is not None, f"expected non-None for: {raw!r}"
        assert set(result.keys()) == expected_keys, (
            f"key mismatch for {raw!r}: got {set(result.keys())}"
        )


def test_pihole_schema_declarations_stay_ordered_and_in_lockstep() -> None:
    """All three Pi-hole row declarations must agree on populated and empty shape."""
    result = parse_line(_line("query[A] example.test from 192.0.2.1"))
    assert result is not None
    parser_columns = tuple(result)
    assert parser_columns == tuple(_PIHOLE_COLUMNS) == tuple(_DNS_PIHOLE_EMPTY_COLUMNS), (
        "a narrowing that touches two of the three sites leaves populated and "
        "empty Pi-hole frames disagreeing on shape"
    )


def test_sniff_recognizes_dns_bearing_event_after_row_narrowing() -> None:
    """Sniffing depends on the surviving event_type, not discarded line payload."""
    assert sniff([_line("query[A] example.test from 192.0.2.1")]) == "dns"


# ── dnssec_query event type ───────────────────────────────────────────────────

def test_parse_dnssec_query_ds() -> None:
    raw = _line("dnssec-query[DS] example.test to 198.51.100.53")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "dnssec_query"
    assert result["qtype"] == "DS"
    assert result["query"] == "example.test"
    assert result["src"] is None


def test_parse_dnssec_query_dnskey() -> None:
    raw = _line("dnssec-query[DNSKEY] example.test to 198.51.100.53")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "dnssec_query"
    assert result["qtype"] == "DNSKEY"


def test_parse_dnssec_query_not_forwarded() -> None:
    """dnssec-query lines must not be misclassified as forwarded."""
    raw = _line("dnssec-query[DS] example.test to 198.51.100.53")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] != "forwarded"


# ── special event type ────────────────────────────────────────────────────────

def test_parse_special_domain() -> None:
    raw = _line("special domain example.test is 192.0.2.10")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "special"
    assert result["query"] == "example.test"


def test_parse_special_domain_not_config() -> None:
    """special domain lines must not be misclassified as config."""
    raw = _line("special domain example.test is 192.0.2.10")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] != "config"


def test_parse_special_domain_subdomain_variant() -> None:
    """Subdomain-prefixed special domain (mask-h2 style) is captured correctly."""
    raw = _line("special domain mask-h2.example.test is 192.0.2.10")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "special"
    assert result["query"] == "mask-h2.example.test"


# ── dhcp event type ───────────────────────────────────────────────────────────

def test_parse_dhcp_ip_then_hostname() -> None:
    """DHCP <ip> is <hostname> field order parses to dhcp with DNS fields None."""
    raw = _line("DHCP 192.0.2.50 is myhost.test")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "dhcp"
    assert result["query"] is None
    assert result["src"] is None
    assert result["qtype"] is None


def test_parse_dhcp_hostname_then_ip() -> None:
    """DHCP <hostname> is <ip> field order also parses to dhcp with DNS fields None."""
    raw = _line("DHCP myhost.test is 192.0.2.50")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "dhcp"
    assert result["query"] is None
    assert result["src"] is None
    assert result["qtype"] is None


def test_parse_unknown_still_works() -> None:
    """Genuinely unrecognized inner messages still fall through to event_type 'unknown'."""
    raw = _line("something totally unrecognized xyz-12345")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "unknown"
    assert result["query"] is None


# ── pihole_hostname event type ────────────────────────────────────────────────

def test_parse_pihole_hostname_address() -> None:
    raw = _line("Pi-hole hostname pihole.test is 192.0.2.1")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "pihole_hostname"
    assert result["query"] == "pihole.test"


def test_parse_pihole_hostname_nodata() -> None:
    """NODATA form retains the Pi-hole-hostname grammar verdict."""
    raw = _line("Pi-hole hostname pihole.test is NODATA")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "pihole_hostname"


def test_parse_pihole_hostname_not_config() -> None:
    """Pi-hole hostname lines must not be misclassified as config."""
    raw = _line("Pi-hole hostname pihole.test is 192.0.2.1")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] != "config"


def test_parse_pihole_hostname_unknown_still_unknown() -> None:
    """Genuinely unrecognized lines are unaffected by the pihole_hostname grammar."""
    raw = _line("something totally unrecognized xyz-99999")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "unknown"
    assert result["query"] is None


# ── regex_blocked event type ──────────────────────────────────────────────────

def test_parse_regex_blocked_denied_address() -> None:
    """Primary regex-denied spelling retains its event-type verdict."""
    raw = _line("regex denied telemetry.example.test is 0.0.0.0")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "regex_blocked"
    assert result["query"] == "telemetry.example.test"


def test_parse_regex_blocked_not_config() -> None:
    """regex denied lines must not be misclassified as config."""
    raw = _line("regex denied telemetry.example.test is 0.0.0.0")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] != "config"


def test_parse_regex_blocked_not_gravity_blocked() -> None:
    """regex_blocked is a distinct event type from gravity_blocked."""
    raw = _line("regex denied telemetry.example.test is 0.0.0.0")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] != "gravity_blocked"


def test_parse_regex_blacklisted_variant() -> None:
    """'regex blacklisted' spelling also maps to regex_blocked."""
    raw = _line("regex blacklisted tracker.example.test is 0.0.0.0")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "regex_blocked"


def test_parse_exactly_denied_variant() -> None:
    """'exactly denied' spelling also maps to regex_blocked."""
    raw = _line("exactly denied tracker.example.test is 0.0.0.0")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "regex_blocked"


def test_parse_regex_blocked_nodata_answer() -> None:
    """NODATA form retains the regex-blocked grammar verdict."""
    raw = _line("regex denied telemetry.example.test is NODATA")
    result = parse_line(raw)
    assert result is not None
    assert result["event_type"] == "regex_blocked"


def test_parse_canary_domain_still_unknown() -> None:
    """DoH/DDR canary dispositions are not promoted - they stay in the unknown bucket."""
    canary_lines = [
        _line("Designated Resolver domain example.invalid is NODATA"),
        _line("Mozilla canary domain example.invalid is NXDOMAIN"),
    ]
    for raw in canary_lines:
        result = parse_line(raw)
        assert result is not None, f"expected non-None for: {raw!r}"
        assert result["event_type"] == "unknown", (
            f"expected unknown for canary line, got {result['event_type']!r}"
        )
