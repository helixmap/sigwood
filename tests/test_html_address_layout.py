"""Address identity, escaping and layout affordances on the real output path."""

from collections import Counter
from dataclasses import replace
from html.parser import HTMLParser

import pytest

from tests.html_layout_cases import layout_cases, layout_summary, IP4, IP6, PEER6
from sigwood.outputs import _render_model as model
from sigwood.outputs._render_model import Cell, html_cell_value, project_row
from sigwood.outputs._sanitize import strip_control
from sigwood.outputs.html import _projected_cell, _styles, render_report_html


class Markup(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.text = ""
        self.tags = []
        self.tokens = []
        self.token_depth = 0
        self.max_token_depth = 0
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "span" and dict(attrs).get("class") == "tok":
            self.tokens.append("")
            self.token_depth += 1
            self.max_token_depth = max(self.max_token_depth, self.token_depth)

    def handle_endtag(self, tag):
        if tag == "span" and self.token_depth:
            self.token_depth -= 1

    def handle_data(self, data):
        self.text += data
        if self.token_depth:
            self.tokens[-1] += data


@pytest.mark.parametrize("case", layout_cases(), ids=lambda c: c.name)
def test_projection_inventory_and_exact_visible_text(case):
    cells = project_row(case.finding)
    expected = dict(case.addresses)
    assert {i: c.address_tokens for i, c in enumerate(cells) if c.address_tokens} == expected
    assert tuple(i for i, c in enumerate(cells) if c.nowrap) == case.nowrap_columns
    for cell in cells:
        parsed = Markup(_projected_cell(cell, case.finding.detector))
        assert parsed.text == strip_control(html_cell_value(cell))
        assert parsed.tokens == [strip_control(t) for t in cell.address_tokens]
        assert parsed.max_token_depth <= 1
        assert all(tag in ("span", "wbr") for tag, _ in parsed.tags)
        assert all(attrs == ({"class": "tok"} if tag == "span" else {})
                   for tag, attrs in parsed.tags)


@pytest.mark.parametrize(("value", "tokens"), [
    (f"{IP6} -> {IP6}:443/tcp", (IP6, IP6)),
    ("192.0.2.1 -> 192.0.2.11", ("192.0.2.1", "192.0.2.11")),
    ("192.0.2.11 -> 192.0.2.1", ("192.0.2.11", "192.0.2.1")),
    ("&amp; then amp", ("&amp;", "amp")),
    ('before </span><wbr><script>"&\x00 after', ('</span><wbr><script>"&\x00',)),
    ("flow=" + IP4 + " -> " + PEER6, (IP4, PEER6)),
])
def test_original_slices_emit_exact_text_with_constant_markup(value, tokens):
    cell = Cell("flow", value, address_tokens=tokens)
    parsed = Markup(_projected_cell(cell, "protocol"))
    assert parsed.text == strip_control(html_cell_value(cell))
    assert parsed.tokens == [strip_control(t) for t in tokens]
    assert parsed.max_token_depth == 1
    assert parsed.tags == [("span", {"class": "tok"})] * len(tokens)


@pytest.mark.parametrize("tokens", [("absent",), (IP4, IP4), ("",), (PEER6, IP4)])
def test_invalid_ordered_declaration_fails_at_projection(monkeypatch, tokens):
    monkeypatch.setitem(model._PROJECTORS, "custom", lambda f: [
        Cell(None, f"{IP4} -> {PEER6}", address_tokens=tokens)])
    finding = next(c.finding for c in layout_cases() if c.name == "generic")
    with pytest.raises(ValueError, match="address token must occur in order"):
        project_row(finding)


@pytest.mark.parametrize("detector, evidence", [
    ("beacon", {"src_ip": "", "dst_ip": None}),
    ("ssl", {"src": None, "dst": ""}),
    ("exfil", {}), ("scan", {"scan_type": "vertical"}),
    ("dnsblock", {"kind": "arrival", "address": ""}),
    ("protocol", {"kind": "unlabeled", "src": None}),
    ("auth", {"source": ""}),
])
def test_absent_evidence_never_declares_an_empty_token(detector, evidence):
    f = replace(layout_cases()[0].finding, detector=detector, title="", evidence=evidence)
    assert not any(c.address_tokens for c in project_row(f))


@pytest.mark.parametrize("detector, evidence", [
    ("dns", {"tier": "unscanned_clusters"}),
    ("dns", {"tier": "scan_summary"}),
    ("aws", {"tier": "ranked_summary"}),
    ("protocol", {"kind": "context"}),
    ("dnsblock", {"kind": "recurring_activity"}),
    ("dnsblock", {"kind": "prior_handling_exclusions"}),
    ("dnsblock", {}),
])
def test_full_width_rows_have_no_address_or_soft_break_affordance(detector, evidence):
    f = replace(layout_cases()[0].finding, detector=detector, title="example.org/path", evidence=evidence)
    cell, = project_row(f)
    assert cell.full_width and not cell.nowrap and not cell.address_tokens
    assert not Markup(_projected_cell(cell, detector)).tags


def test_real_report_has_exact_declared_token_population():
    cases = layout_cases()
    result = Markup(render_report_html([c.finding for c in cases], layout_summary(), verbose_level=0))
    expected = Counter(t for c in cases for _, ts in c.addresses for t in ts)
    assert Counter(result.tokens) == expected
    assert result.max_token_depth == 1


def test_soft_breaks_are_escape_safe_and_explicitly_limited():
    value = '</td><wbr><img src="file:///example">a.b/c:d&example;'
    for detector, separators in (("dns", "."), ("aws", "./:"), ("custom", "")):
        parsed = Markup(_projected_cell(Cell(None, value), detector))
        assert parsed.text == value
        assert parsed.tags == [("wbr", {})] * sum(value.count(c) for c in separators)
        assert not Markup(_projected_cell(Cell("data", value), detector)).tags


def test_screen_affordances_do_not_escape_their_media_scope():
    css = _styles(True, ssl_reason_wrap=True)
    before, screen = css.split("@media screen {", 1)
    screen, printed = screen.split("@media print {", 1)
    assert "span.tok { white-space: nowrap; }" in before
    assert ".kv .v { overflow-wrap: break-word; }" in before
    assert "word-break: break-word" not in css
    assert ".findings-table td.nowrap { white-space: nowrap; }" in screen
    assert ".table-scroll { overflow-x: auto; }" in screen
    assert "td.nowrap" not in printed and "overflow-x" not in printed
    assert ".findings-table td:not(.data), .kv .v, .findings-table td.col-reason { overflow-wrap: anywhere; }" in printed
    assert ".findings-table:not(.syslog-table) { font-size: 12px; }" in printed
    assert ".findings-table:not(.syslog-table) th, .findings-table:not(.syslog-table) td { padding-right: 6px; }" in printed
    assert ".findings-table .kv .k { padding-right: 10px; }" in printed
    for selector in (".notes td", ".meat-line", ".sample-line"):
        rule = css.split(selector + " {", 1)[1].split("}", 1)[0]
        assert "overflow-wrap: anywhere" in rule


def test_syslog_keeps_its_own_table_without_a_scroller():
    cases = layout_cases()
    for detector in {c.finding.detector for c in cases}:
        out = render_report_html([c.finding for c in cases if c.finding.detector == detector], layout_summary(), verbose_level=0)
        wrapper_count = out.count('<div class="table-scroll">')
        table_count = out.count('<table class="findings-table')
        assert wrapper_count == (0 if detector == "syslog" else table_count)
        if detector == "custom":
            assert '<td class="nowrap" colspan="1">' in out
