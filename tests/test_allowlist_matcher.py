"""Parity + routing tests for the vectorized domain-allowlist match engine.

The vectorized two-lane engine (`_compile_domain_patterns` + `_match_distinct`)
must be byte-identical to the historical per-row logic - the ORACLE below, a
verbatim copy of that logic, is the reference. The ONE intended behavior change
is malformed `re:` handling: today it raises `re.error` mid-run; now it is dropped
and recorded. NO timing assertions - correctness only.

Privacy rail: RFC-reserved (`example.com`) / `.test` / obvious-synthetic domains
only; never real shipped domains.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch

import pandas as pd

import sigwood.common.allowlist as al


# ── ORACLE - the historical per-row logic, verbatim ───────────────────────────


def _oracle_allowed(patterns: list[str], domain) -> bool:
    """Oracle for the domain-match contract: lower the data, IGNORECASE on `re:`,
    lower the glob pattern. VALID patterns only (a malformed `re:` raises here)."""
    dl = str(domain).lower()
    for p in patterns:
        if p.startswith("re:"):
            if re.search(p[3:], dl, re.IGNORECASE):
                return True
        else:
            if fnmatch(dl, p.lower()):
                return True
    return False


def _oracle_drop(patterns: list[str], q) -> bool:
    """The two-probe oracle: bare query OR apex probe."""
    return _oracle_allowed(patterns, str(q)) or _oracle_allowed(patterns, "x." + str(q))


# A diverse VALID matrix - globs (exact, prefix-`*`, `?`, mid-`*`, uppercase) and
# `re:` (internal `|`+`$`, a capturing group that routes to fallback).
VALID_PATTERNS: list[str] = [
    "example.com",
    "*.example.com",
    "h?st.example.org",
    "ab?cd*.test",
    "UPPER.example.net",
    r"re:\.foo\.net$",
    r"re:(?:alpha|beta)\.svc\.test$",
    r"re:(grp)\.cap\.test$",            # capturing group → fallback lane
]

# Domains incl. suffix-trap, prefix-trap, case variants, apex probe, NaN, int, dup.
MATRIX_DOMAINS: list = [
    "example.com",
    "notexample.com",                  # suffix-trap → NO
    "example.com.evil.test",           # prefix-trap → NO
    "EXAMPLE.COM",
    "a.example.com",
    "host.example.com",
    "hxst.example.org",
    "abXcdYYY.test",
    "upper.example.net",
    "x.foo.net",
    "deep.foo.net",
    "alpha.svc.test",
    "beta.svc.test",
    "gamma.svc.test",                  # NO (alternation)
    "grp.cap.test",
    "foo.net",                         # bare misses `\.foo\.net$`, matches via x.
    float("nan"),
    12345,
    "example.com",                     # duplicate
]


def _drop_index_set(df: pd.DataFrame, filtered: pd.DataFrame) -> set:
    return set(df.index) - set(filtered.index)


def test_filter_and_count_parity_duplicate_heavy() -> None:
    """Filter drop-set AND coverage count match the oracle over a DUPLICATE-HEAVY
    frame (this is what validates the dedup broadcast)."""
    m = al.AllowlistMatcher(domain_patterns=VALID_PATTERNS)
    df = pd.DataFrame({"query": MATRIX_DOMAINS * 100})

    filtered = m.filter_df(df, "dns")
    got_drop = df.index.isin(set(df.index) - set(filtered.index))
    exp_drop = [_oracle_drop(VALID_PATTERNS, q) for q in df["query"]]
    assert list(got_drop) == exp_drop

    exp_count = sum(_oracle_drop(VALID_PATTERNS, q) for q in df["query"])
    assert m.count_domain_suppressed(df) == exp_count
    # The traps and apex probe are pinned explicitly (not just via the oracle).
    one = al.AllowlistMatcher(domain_patterns=["example.com", r"re:\.foo\.net$"])
    assert one.is_domain_allowed("example.com")
    assert not one.is_domain_allowed("notexample.com")
    assert not one.is_domain_allowed("example.com.evil.test")
    assert one.is_domain_allowed("x.foo.net")
    # apex via the "x." probe: bare "foo.net" has no leading dot so `\.foo\.net$`
    # misses it, but the "x." apex probe ("x.foo.net") matches → row dropped.
    assert not one.is_domain_allowed("foo.net")          # bare misses
    apex = pd.DataFrame({"query": ["foo.net"]})
    assert len(one.filter_df(apex, "dns")) == 0          # dropped via x.-probe


def test_case_and_scoped_flag_parity_both_directions() -> None:
    """Scoped case flags pin lower-before-match - the exact drift IGNORECASE-alone
    would introduce, in BOTH directions."""
    pats = [r"re:(?-i:example)\.test$", r"re:(?-i:UPPER)\.test$"]
    m = al.AllowlistMatcher(domain_patterns=pats)
    domains = ["example.test", "EXAMPLE.test", "ExAmPlE.test",
               "UPPER.test", "upper.test", "Upper.test"]
    df = pd.DataFrame({"query": domains})

    got = set(_drop_index_set(df, m.filter_df(df, "dns")))
    exp = {i for i, q in enumerate(domains) if _oracle_drop(pats, q)}
    assert got == exp
    # Direction 1: the data is lowered, so (?-i:example) matches every casing.
    assert all(m.is_domain_allowed(d) for d in ["example.test", "EXAMPLE.test", "ExAmPlE.test"])
    # Direction 2: (?-i:UPPER) requires literal "UPPER" but the data is lowered to
    # "upper" → matches NOTHING (IGNORECASE-over-original would wrongly match).
    assert not any(m.is_domain_allowed(d) for d in ["UPPER.test", "upper.test", "Upper.test"])


def test_two_lane_routing_unsafe_shapes() -> None:
    """A capturing group, a named group, a backreference, and a GLOBAL inline flag
    each route to the FALLBACK lane (the union stays zero-capturing) AND still
    match correctly (parity vs oracle)."""
    glob = "*.union.test"
    cap = r"re:(grp)\.cap\.test$"        # capturing group
    named = r"re:(?P<n>nm)\.test$"       # named group
    backref = r"re:(ab)\1\.ref\.test$"   # capturing + backreference
    inline = r"re:(?i)inl\.test$"        # global inline flag
    pats = [glob, cap, named, backref, inline]
    m = al.AllowlistMatcher(domain_patterns=pats)

    # Routing: 4 unsafe → fallback; the glob → union; union has ZERO groups.
    assert len(m._domain_fallback) == 4
    assert m._domain_regex is not None
    assert m._domain_regex.groups == 0
    assert not m.malformed_patterns

    # Each still matches (parity): construct the expected via oracle and the engine.
    domains = ["a.union.test", "grp.cap.test", "nm.test", "abab.ref.test",
               "inl.test", "INL.test", "miss.test"]
    df = pd.DataFrame({"query": domains})
    got = _drop_index_set(df, m.filter_df(df, "dns"))
    exp = {i for i, q in enumerate(domains) if _oracle_drop(pats, q)}
    assert got == exp
    # inline flag → case-insensitive in BOTH oracle and engine (the data is also
    # lowered, so this is doubly true), miss stays out.
    assert m.is_domain_allowed("INL.test")
    assert not m.is_domain_allowed("miss.test")


def test_union_only_globs_zero_groups() -> None:
    m = al.AllowlistMatcher(domain_patterns=["example.com", "*.example.com"])
    assert m._domain_regex is not None
    assert m._domain_regex.groups == 0
    assert m._domain_fallback == []


def test_malformed_re_dropped_and_recorded_with_provenance() -> None:
    """A malformed `re:` is dropped (does not crash) - sibling patterns still
    match - and recorded with (source, lineno) when sources are supplied."""
    pats = ["good.example.com", "re:(badopen", r"re:\.ok\.test$"]
    sources = [("/cfg/domains_bad.txt", 4), ("/cfg/domains_bad.txt", 5),
               ("/cfg/domains_bad.txt", 6)]
    m = al.AllowlistMatcher(domain_patterns=pats, domain_pattern_sources=sources)

    assert [mp.pattern for mp in m.malformed_patterns] == ["re:(badopen"]
    mp = m.malformed_patterns[0]
    assert mp.source == "/cfg/domains_bad.txt"
    assert mp.lineno == 5
    # Sibling patterns still match - the bad one is simply absent.
    assert m.is_domain_allowed("good.example.com")
    assert m.is_domain_allowed("host.ok.test")
    assert not m.is_domain_allowed("nope.test")


def test_malformed_without_sources_has_none_provenance() -> None:
    m = al.AllowlistMatcher(domain_patterns=["re:(badopen"])
    assert len(m.malformed_patterns) == 1
    assert m.malformed_patterns[0].source is None
    assert m.malformed_patterns[0].lineno is None
    # All patterns dropped → no domain matching can fire.
    assert not m._has_domain_patterns()


def test_provenance_length_mismatch_raises() -> None:
    """A desynced domain_pattern_sources list must fail loudly, NOT silently
    truncate (zip) and drop suppression for the unpaired patterns - a fail-open
    loss of allowlist coverage. Both directions raise."""
    import pytest

    pats = ["a.example.com", "b.example.com"]
    with pytest.raises(ValueError, match="lockstep drift"):
        al.AllowlistMatcher(domain_patterns=pats,
                            domain_pattern_sources=[("f", 1)])           # short
    with pytest.raises(ValueError, match="lockstep drift"):
        al.AllowlistMatcher(domain_patterns=pats,
                            domain_pattern_sources=[("f", 1), ("f", 2), ("f", 3)])  # long


def test_edge_cases_empty_and_missing_column() -> None:
    m = al.AllowlistMatcher(domain_patterns=["example.com"])
    # Empty frame → 0 and an empty filtered frame.
    empty = pd.DataFrame({"query": []})
    assert m.count_domain_suppressed(empty) == 0
    assert len(m.filter_df(empty, "dns")) == 0
    # No `query` column → count 0 (filter routes to numeric path, not exercised).
    noq = pd.DataFrame({"src": ["192.0.2.10"], "dst": ["198.51.100.20"],
                        "port": [443], "proto": ["tcp"]})
    assert m.count_domain_suppressed(noq) == 0
    # No patterns at all → filter is a pass-through copy, count 0.
    none = al.AllowlistMatcher()
    df = pd.DataFrame({"query": ["anything.test"]})
    assert len(none.filter_df(df, "dns")) == 1
    assert none.count_domain_suppressed(df) == 0


# ── system-log host patterns: bare-only engine + dispatch ────────────────────


def test_host_filter_count_casefold_regex_and_no_apex_probe() -> None:
    patterns = ["lab-*", r"re:(?-i:kiosk)-[0-9]+$", "foo.example"]
    matcher = al.AllowlistMatcher(host_patterns=patterns)
    df = pd.DataFrame({
        "host": [
            "LAB-1", "lab-1", "KIOSK-2", "foo.example",
            "x.foo.example", float("nan"),
        ],
        "message": ["m"] * 6,
    })

    filtered = matcher.filter_df(df, "syslog")
    assert filtered["host"].tolist()[:1] == ["x.foo.example"]
    assert len(filtered) == 2
    count, hosts = matcher.count_host_suppressed(df)
    assert count == 4
    assert hosts == {"lab-1", "kiosk-2", "foo.example"}


def test_host_scoped_uppercase_body_stays_exact_after_lowering() -> None:
    matcher = al.AllowlistMatcher(host_patterns=[r"re:(?-i:UPPER)-host$"])
    df = pd.DataFrame({"host": ["UPPER-host", "upper-host"]})
    assert len(matcher.filter_df(df, "syslog")) == 2
    assert matcher.count_host_suppressed(df) == (0, set())


def test_query_wins_over_host_and_nonquery_frames_dispatch_narrowly() -> None:
    matcher = al.AllowlistMatcher(host_patterns=["chatty-*"])
    pihole = pd.DataFrame({
        "query": ["keep.example"], "host": ["chatty-dns"],
        "message": ["query[A] keep.example"],
    })
    syslog = pd.DataFrame({"host": ["chatty-flat", "keep-flat"],
                           "message": ["a", "b"]})
    conn = pd.DataFrame({"src": ["192.0.2.1"], "dst": ["198.51.100.1"]})
    cloudtrail = pd.DataFrame({"event_name": ["ListThings"]})

    assert matcher.filter_df(pihole, "dns").equals(pihole)
    assert matcher.filter_df(syslog, "syslog")["host"].tolist() == ["keep-flat"]
    assert matcher.filter_df(conn, "beacon").equals(conn)
    assert matcher.filter_df(cloudtrail, "aws").equals(cloudtrail)


def test_numeric_filter_precedes_host_filter_on_nonquery_frame() -> None:
    matcher = al.AllowlistMatcher(
        numeric_rules=[al.NumericRule(port=22)], host_patterns=["chatty-*"],
    )
    df = pd.DataFrame({
        "src": ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
        "dst": ["198.51.100.1", "198.51.100.2", "198.51.100.3"],
        "port": [22, 443, 443], "proto": ["tcp", "tcp", "tcp"],
        "host": ["keep", "chatty-box", "keep"],
    })
    assert matcher.filter_df(df, "syslog").index.tolist() == [2]


def test_host_malformed_patterns_follow_domain_with_provenance() -> None:
    matcher = al.AllowlistMatcher(
        domain_patterns=["re:(bad-domain"],
        domain_pattern_sources=[("domains_test", 2)],
        host_patterns=["re:(bad-host", "keep-*"],
        host_pattern_sources=[("hosts_test", 4), ("hosts_test", 5)],
    )
    assert [item.pattern for item in matcher.malformed_patterns] == [
        "re:(bad-domain", "re:(bad-host",
    ]
    assert matcher.malformed_patterns[1].source == "hosts_test"
    assert matcher.malformed_patterns[1].lineno == 4
    assert matcher.filter_df(pd.DataFrame({"host": ["keep-one"]}), "syslog").empty


def test_host_provenance_length_mismatch_raises() -> None:
    import pytest

    with pytest.raises(ValueError, match="host_pattern_sources length.*lockstep drift"):
        al.AllowlistMatcher(
            host_patterns=["one", "two"],
            host_pattern_sources=[("hosts_test", 1)],
        )


def test_host_empty_and_missing_column_short_circuits() -> None:
    matcher = al.AllowlistMatcher(host_patterns=["chatty-*"])
    empty = pd.DataFrame({"host": []})
    missing = pd.DataFrame({"message": ["x"]})
    assert matcher.filter_df(empty, "syslog") is empty
    assert matcher.count_host_suppressed(empty) == (0, set())
    assert matcher.count_host_suppressed(missing) == (0, set())


def test_load_pattern_file_lines_original_linenos(tmp_path) -> None:
    """`load_pattern_file_lines` reports the ORIGINAL line number (before strip);
    `load_pattern_file` delegates to it (same patterns, no drift)."""
    p = tmp_path / "domains.txt"
    p.write_text(
        "# header comment\n"
        "\n"
        "first.example.com\n"
        "   # indented comment\n"
        "second.example.com   # trailing\n",
        encoding="utf-8",
    )
    lines = al.load_pattern_file_lines(p)
    assert lines == [("first.example.com", 3), ("second.example.com", 5)]
    assert al.load_pattern_file(p) == ["first.example.com", "second.example.com"]
