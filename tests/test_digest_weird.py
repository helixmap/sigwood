"""The weird digest card.

Coverage differs BY STATISTIC: a cliff gates and so has speaking and silent
cases; a dist never gates and so has always-speaking coverage instead.
Addresses are RFC 5737 documentation space.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from sigwood.digest.weird import summarize

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "weird" / "weird.log"


def _frame(names, hosts=None, sources=None) -> pd.DataFrame:
    n = len(names)
    return pd.DataFrame({
        "ts": [1785000000.0 + i * 60 for i in range(n)],
        "name": names,
        "src": hosts if hosts is not None else [f"192.0.2.{10 + i}" for i in range(n)],
        "source": sources if sources is not None else ["TCP"] * n,
    })


def _fields(body) -> dict:
    return {f.label: f.cells for f in body["fields"]}


def _ambient(body) -> dict:
    return dict(body["zone1_extras"])


# ── the two cliffs: speaking and silent ───────────────────────────────────────

def test_name_volume_speaks_when_one_name_towers() -> None:
    names = ["window_recision"] * 12 + ["a", "b", "c", "d", "e"]
    body = summarize(_frame(names))
    assert any("window_recision is the most frequent weird" in i for i in body["insights"])


def test_name_volume_is_silent_below_the_gate() -> None:
    names = ["a"] * 5 + ["b"] * 4 + ["c", "d", "e"]
    body = summarize(_frame(names))
    assert "name-volume" not in _fields(body)
    assert not any("most frequent weird" in i for i in body["insights"])


def test_name_volume_is_silent_below_the_population_floor() -> None:
    """Four distinct names cannot clear a floor of five, whatever the ratio."""
    names = ["a"] * 20 + ["b", "c", "d"]
    body = summarize(_frame(names))
    assert "name-volume" not in _fields(body)


def test_host_volume_speaks_when_one_host_towers() -> None:
    hosts = ["192.0.2.10"] * 12 + [f"192.0.2.{20 + i}" for i in range(5)]
    body = summarize(_frame([f"n{i}" for i in range(len(hosts))], hosts=hosts))
    assert any("192.0.2.10 raises" in i for i in body["insights"])


def test_host_volume_is_silent_below_the_gate() -> None:
    hosts = ["192.0.2.10"] * 5 + ["192.0.2.11"] * 4 + ["192.0.2.12", "192.0.2.13", "192.0.2.14"]
    body = summarize(_frame([f"n{i}" for i in range(len(hosts))], hosts=hosts))
    assert "host-volume" not in _fields(body)


# ── the two dists: always speaking ────────────────────────────────────────────

def test_both_distributions_speak_on_a_quiet_file() -> None:
    """Neither cliff clears its gate; the card still orients and dashes nothing."""
    names = ["a"] * 3 + ["b"] * 3 + ["c", "d", "e"]
    body = summarize(_frame(names))
    fields = _fields(body)
    assert set(fields) == {"name-mix", "analyzer-mix"}
    assert body["insights"] == []
    assert all("-" != cell for cells in fields.values() for cell in cells)


def test_distributions_survive_a_single_category_pile() -> None:
    body = summarize(_frame(["window_recision"] * 9))
    fields = _fields(body)
    assert fields["name-mix"] == ["window_recision 100%"]
    assert fields["analyzer-mix"] == ["TCP 100%"]


def test_distributions_disclose_hidden_categories() -> None:
    names = ["a"] * 50 + ["b"] * 30 + ["c"] * 15 + ["d"] * 5
    sources = ["TCP"] * 50 + ["UDP"] * 30 + ["ICMP"] * 15 + ["OTHER"] * 5
    fields = _fields(summarize(_frame(names, sources=sources)))
    assert fields["name-mix"] == ["a 50% · b 30% · c 15% · (other) 5%"]
    assert fields["analyzer-mix"] == ["TCP 50% · UDP 30% · ICMP 15% · (other) 5%"]


def test_distribution_positive_remainder_below_one_percent_is_visible() -> None:
    names = ["a"] * 1000 + ["b"] * 500 + ["c"] * 100 + ["d"]
    assert _fields(summarize(_frame(names)))["name-mix"][0].endswith(
        " · (other) <1%"
    )


def test_absent_analyzer_becomes_a_category_in_the_all_row_denominator() -> None:
    """A weird raised outside a protocol analyzer is an ordinary kind, so its
    rows stay in the denominator rather than letting the rest overstate."""
    body = summarize(_frame(["a", "b", "c", "d"], sources=["TCP", "TCP", None, None]))
    assert _fields(body)["analyzer-mix"] == ["TCP 50% · (no analyzer) 50%"]


def test_absent_analyzer_column_renders_the_whole_mix_as_that_category() -> None:
    frame = _frame(["a", "b"]).drop(columns=["source"])
    assert _fields(summarize(frame))["analyzer-mix"] == ["(no analyzer) 100%"]


def test_name_mix_excludes_nameless_rows_from_its_denominator() -> None:
    """The deliberate asymmetry with analyzer-mix: a nameless weird row is
    malformed rather than a kind of weird, so it is given no category."""
    frame = _frame(["a", "a", None, None])
    assert _fields(summarize(frame))["name-mix"] == ["a 100%"]


# ── the ambient block ─────────────────────────────────────────────────────────

def test_ambient_reports_the_hostless_count_when_present() -> None:
    frame = _frame(["a", "b", "c"], hosts=["192.0.2.10", None, None])
    ambient = _ambient(summarize(frame))
    assert ambient["hosts"] == "1"
    assert ambient["rows without origin host"] == "2"


def test_ambient_omits_the_hostless_row_at_zero() -> None:
    ambient = _ambient(summarize(_frame(["a", "b"])))
    assert "rows without origin host" not in ambient


def test_hostless_rows_change_neither_the_host_cliff_nor_its_denominator() -> None:
    hosts = ["192.0.2.10"] * 12 + [f"192.0.2.{20 + i}" for i in range(5)]
    names = [f"n{i}" for i in range(len(hosts))]
    without = summarize(_frame(names, hosts=hosts))
    with_holes = summarize(_frame(names + ["x", "y"], hosts=hosts + [None, None]))
    # A speaking cliff is PROMOTED to an insight and suppressed from fields, so
    # the insight text is where the measurement is compared.
    host_lines = [
        [i for i in body["insights"] if "raises" in i]
        for body in (without, with_holes)
    ]
    assert host_lines[0] == host_lines[1] != []


# ── categories that render alike are counted alike ────────────────────────────

def test_categories_differing_only_by_a_control_byte_count_together() -> None:
    frame = _frame(["window_recision", "window_recision\x1b", "b", "c"])
    assert _fields(summarize(frame))["name-mix"][0].startswith("window_recision 50%")


# ── the real route ────────────────────────────────────────────────────────────

def test_the_checked_in_fixture_renders_through_the_real_cli_route(capsys) -> None:
    """The body must reach the runner-owned DigestCard through the real sniff
    route - a hand-built card would mask integration drift."""
    from sigwood.cli import main

    rc = main(["digest", str(FIXTURE)])
    out = capsys.readouterr().out
    assert (rc or 0) == 0
    assert "weird · 20 lines" in out
    assert "no digest card" not in out
    assert "Unrecognized source" not in out
    assert "name-mix:" in out and "analyzer-mix:" in out
    assert "rows without origin host: 1" in out
