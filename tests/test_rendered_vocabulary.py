"""Rendered-output vocabulary tripwires over real sigwood render paths.

Graph metadata is a named gap: this audit does not cover graph output.
All fixtures are synthetic and use RFC 5737 addresses and reserved names.
"""

from __future__ import annotations

import copy
import io
import json
import re
from datetime import datetime, timezone
from html import escape
from html.parser import HTMLParser
from typing import Iterable, Iterator, Mapping, Pattern

import pytest

import sigwood.outputs.html as html_output
from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.era import EraCard, render_text_report
from sigwood.outputs.html import render_report_html
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler
from tests.test_digest_blob import _text_blob_card
from tests.test_era_report import _full_deck
from tests.test_syslog_detector import _BASE_TS, _common_row, _run_with
from tests.test_text_output import _digest_card


# outputs.md: tier is internal design vocabulary; "needle" and its peer terms
# never reach a reader. "member finding" pins the prior leaked renderer label.
CLASS_B = {"needle", "member finding"}
# Shipped era regression: internal decision identifiers must not reach output.
D_PATTERN = re.compile(r"\bD\d{1,3}\b")

_CLASS_B_PREDICATES = tuple(
    (token, re.compile(re.escape(token), re.IGNORECASE))
    for token in sorted(CLASS_B)
)
_TEXT_PREDICATES = _CLASS_B_PREDICATES
_ERA_PREDICATES = (("D-code", D_PATTERN),) + _CLASS_B_PREDICATES
_DNSBLOCK_PREDICATES = _TEXT_PREDICATES + (
    ("history_seconds", re.compile(r"\bhistory_seconds\b", re.IGNORECASE)),
    ("arrival_fold", re.compile(r"\barrival_fold\b", re.IGNORECASE)),
    ("campaign", re.compile(r"\bcampaign\b", re.IGNORECASE)),
    ("calibration", re.compile(r"\bcalibrat(?:e|ed|ion)\b", re.IGNORECASE)),
    ("ratified", re.compile(r"\bratified\b", re.IGNORECASE)),
)
_DNSBLOCK_HUMAN_LEGIBILITY = (
    ("bare periods", re.compile(r"\bperiods\b", re.IGNORECASE)),
    ("prior=", re.compile(r"\bprior=")),
    ("names withheld", re.compile(r"\bnames withheld\b", re.IGNORECASE)),
    ("available rows", re.compile(r"\bavailable rows\b", re.IGNORECASE)),
    ("blocked-logged", re.compile(r"\bblocked-logged\b", re.IGNORECASE)),
    (
        "family-keyed qualifying-name arrivals",
        re.compile(r"\bfamily-keyed qualifying-name arrivals\b", re.IGNORECASE),
    ),
    ("covered export periods", re.compile(r"\bcovered export periods\b", re.IGNORECASE)),
    ("prior periods", re.compile(r"\bprior periods\b", re.IGNORECASE)),
    ("eligible periods", re.compile(r"\beligible periods\b", re.IGNORECASE)),
    (
        "report period strongly covered",
        re.compile(r"\breport period strongly covered\b", re.IGNORECASE),
    ),
)
_SEPARATOR_PATTERN = re.compile(r"^\[([HMLI])\] · (.+?) · (\d+) rare lines?$")


def _string_leaves(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for member in value.values():
            yield from _string_leaves(member)
    elif isinstance(value, (tuple, list)):
        for member in value:
            yield from _string_leaves(member)
    elif isinstance(value, (set, frozenset)):
        for member in sorted(value, key=repr):
            yield from _string_leaves(member)


def scan(text: str, predicates: Iterable[tuple[str, Pattern[str]]]) -> list[str]:
    """Return stable, de-duplicated labels for lexical predicates that match."""
    return [label for label, predicate in predicates if predicate.search(text)]


def premise_holds(
    inputs: object, predicates: Iterable[tuple[str, Pattern[str]]]
) -> list[str]:
    """Report tokens already present in the route's log-derived inputs."""
    found: list[str] = []
    for leaf in _string_leaves(inputs):
        for label in scan(leaf, predicates):
            if label not in found:
                found.append(label)
    return found


class _VisibleBodyParser(HTMLParser):
    """Collect body-visible text and transaction separator divs."""

    _IGNORED = {"head", "style", "script", "noscript"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.transaction_separators: list[str] = []
        self.finding_rows = 0
        self._in_body = False
        self._ignored_tag: str | None = None
        self._separator_depth = 0
        self._separator_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._ignored_tag is not None:
            return
        if tag in self._IGNORED:
            self._ignored_tag = tag
            return
        if tag == "body":
            self._in_body = True
            return
        if not self._in_body:
            return
        classes = set(dict(attrs).get("class", "").split())
        if "finding-row" in classes:
            self.finding_rows += 1
        if self._separator_depth:
            self._separator_depth += 1
        elif tag == "div" and "transaction-member" in classes:
            self._separator_depth = 1
            self._separator_parts = []

    def handle_endtag(self, tag: str) -> None:
        if self._ignored_tag is not None:
            if tag == self._ignored_tag:
                self._ignored_tag = None
            return
        if self._separator_depth:
            self._separator_depth -= 1
            if not self._separator_depth:
                joined = " ".join(" ".join(self._separator_parts).split())
                if joined:
                    self.transaction_separators.append(joined)
                self._separator_parts = []
        if tag == "body":
            self._in_body = False

    def handle_data(self, data: str) -> None:
        if not self._in_body or self._ignored_tag is not None:
            return
        normalized = " ".join(data.split())
        if normalized:
            self.visible.append(normalized)
            if self._separator_depth:
                self._separator_parts.append(normalized)


def _parse_html(document: str) -> _VisibleBodyParser:
    parser = _VisibleBodyParser()
    parser.feed(document)
    parser.close()
    return parser


def _assert_transaction_separators(document: str) -> None:
    separators = _parse_html(document).transaction_separators
    assert separators, "expected at least one transaction-member separator"
    assert all(_SEPARATOR_PATTERN.fullmatch(line) for line in separators), separators


def _controlled_syslog_transaction() -> tuple[list[Finding], tuple[object, ...]]:
    common = [
        {**_common_row(index), "program": "cron", "message": "cron: ordinary event"}
        for index in range(50)
    ]
    anchors = [
        {
            "ts": _BASE_TS + 100_000 + offset,
            "host": "192.0.2.1",
            "program": program,
            "raw": message,
            "message": message,
        }
        for offset, program, message in (
            (0, "sshd", "sshd[*]: Accepted publickey for operator"),
            (1, "sshd", "sshd[*]: Accepted publickey for operator"),
            (30, "sshd", "pam_unix(sshd:session): session closed for user operator"),
            (31, "sshd", "pam_unix(sshd:session): session closed for user operator"),
        )
    ]
    members = [
        {
            "ts": _BASE_TS + 100_010,
            "host": "192.0.2.1",
            "program": "useradd",
            "raw": "useradd: privileged event",
            "message": "useradd: privileged event",
        },
        {
            "ts": _BASE_TS + 100_020,
            "host": "192.0.2.1",
            "program": "cron",
            "raw": "cron: scheduled event",
            "message": "cron: scheduled event",
        },
    ]
    rows = common + anchors + members
    template_ids = [1] * len(common) + [2, 2, 3, 3, 4, 5]
    templates = ["ordinary"] * len(common) + [
        "session-open",
        "session-open",
        "session-close",
        "session-close",
        "privileged-event",
        "scheduled-event",
    ]
    findings = _run_with(rows, template_ids, templates)
    transactions = [
        finding
        for finding in findings
        if finding.evidence.get("tier") == "transaction"
        and finding.evidence.get("members")
    ]
    assert len(transactions) == 1
    carrier = tuple(
        tuple(row.get(field, "") for field in ("host", "program", "raw", "message"))
        for row in rows
    ) + (tuple(templates),)
    return findings, carrier


def _summary() -> RunSummary:
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    return RunSummary(
        data_window=(now, now),
        record_counts={"syslog.example": 56},
        data_size_bytes=4096,
        detectors_run=["syslog"],
        detectors_skipped={},
        detector_missions={
            "syslog": "Mission for syslog.",
            "dnsblock": "Mission for dnsblock.",
        },
    )


def _render_findings_text(findings: list[Finding], level: int) -> str:
    stream = io.StringIO()
    handler = TextHandler(stream=stream, verbose_level=level)
    handler.begin(_summary())
    handler.write(findings)
    return stream.getvalue()


def _render_digest(card: object) -> str:
    stream = io.StringIO()
    TextHandler(stream=stream).render_digest(card)
    return stream.getvalue()


def _render_blob(card: object) -> str:
    stream = io.StringIO()
    TextHandler(stream=stream).render_blob(card)
    return stream.getvalue()


def test_era_full_deck_has_exact_cardinality_and_clean_vocabulary() -> None:
    cards, inputs, declared_abstentions = _full_deck()
    assert premise_holds(inputs, _ERA_PREDICATES) == []

    rendered = render_text_report(cards, family="zeek")
    assert rendered
    titles = tuple(
        line for line in rendered.splitlines()[1:] if line and not line.startswith(" ")
    )
    assert titles == tuple(card.title for card in cards)
    expected_titles = (
        "data-bearing calendar",
        "committed activity",
        "busiest minute",
        "longest connection",
        "largest outbound connection",
        "shape of the week",
        "archive footprint",
        "port-443 transport over time",
        "largest sustained shift",
        "domain arrivals",
    )
    assert titles == tuple(
        f"{number}. {title}"
        for number, title in enumerate(expected_titles, start=1)
    )
    actual_abstentions = frozenset(
        int(card.title.split(".", 1)[0])
        for card in cards
        if any("abstain" in value.casefold() for _label, value in card.facts)
    )
    assert actual_abstentions == declared_abstentions
    assert scan(rendered, _ERA_PREDICATES) == []


def test_era_seeded_tool_label_is_detected() -> None:
    cards, inputs, _declared_abstentions = _full_deck()
    seeded = cards + (EraCard("11. needle seed", (("status", "controlled"),)),)
    assert premise_holds(inputs, _ERA_PREDICATES) == []

    rendered = render_text_report(seeded, family="zeek")
    assert rendered
    assert "needle" in scan(rendered, _ERA_PREDICATES)


def test_real_syslog_transaction_text_is_clean_at_all_levels() -> None:
    findings, inputs = _controlled_syslog_transaction()
    assert premise_holds(inputs, _TEXT_PREDICATES) == []

    for level in (0, 1, 2):
        rendered = _render_findings_text(findings, level)
        assert rendered
        assert scan(rendered, _TEXT_PREDICATES) == []


def test_real_syslog_transaction_html_visible_text_and_separators_are_clean() -> None:
    findings, inputs = _controlled_syslog_transaction()
    assert premise_holds(inputs, _TEXT_PREDICATES) == []

    document = render_report_html(findings, _summary(), verbose_level=2)
    parsed = _parse_html(document)
    assert parsed.finding_rows >= 1
    assert parsed.visible
    assert scan("\n".join(parsed.visible), _TEXT_PREDICATES) == []
    _assert_transaction_separators(document)


def test_dnsblock_history_reading_surfaces_keep_internal_vocabulary_private() -> None:
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    finding = Finding(
        detector="dnsblock",
        severity=Severity.LOW,
        title="192.0.2.7 → example.test",
        description=(
            "These qualifying names were first observed for this address in the "
            "available rows. First is measured against the 21d of history this run "
            "consulted."
        ),
        evidence={
            "kind": "arrival",
            "coverage_lane": "weak",
            "address": "192.0.2.7",
            "family_key": "example.test",
            "qualifying_name_count": 2,
            "attributed_query_count": 6,
            "active_periods": 2,
            "eligible_periods": 5,
            "first_associated_period": "2026-05-12T00:00:00+00:00",
            "history_seconds": 21 * 24 * 60 * 60.0,
            "prior_other_address_count": 0,
            "prior_other_address_count_at_cap": False,
        },
        next_steps=[],
        ts_generated=now,
        data_window=(now, now),
    )
    log_derived_inputs = ("192.0.2.7", "example.test")
    assert premise_holds(log_derived_inputs, _DNSBLOCK_PREDICATES) == []

    for level in (0, 1, 2):
        rendered_text = _render_findings_text([finding], level)
        document = render_report_html([finding], _summary(), verbose_level=level)
        visible_html = "\n".join(_parse_html(document).visible)
        assert "over 21d" in rendered_text
        assert "over 21d" in visible_html
        predicates = (
            _DNSBLOCK_PREDICATES
            if level == 0
            else tuple(
                pair for pair in _DNSBLOCK_PREDICATES
                if pair[0] != "history_seconds"
            )
        )
        assert scan(rendered_text, predicates) == []
        assert scan(visible_html, predicates) == []
        assert scan(rendered_text, _DNSBLOCK_HUMAN_LEGIBILITY) == []
        assert scan(visible_html, _DNSBLOCK_HUMAN_LEGIBILITY) == []

    json_stream = io.StringIO()
    json_handler = JsonHandler(stream=json_stream)
    json_handler.begin(_summary())
    json_handler.write([finding])
    json_handler.end()
    payload = json.loads(json_stream.getvalue())
    public_prose = "\n".join(
        [
            payload["findings"][0]["title"],
            payload["findings"][0]["description"],
            *payload["findings"][0]["next_steps"],
            *payload["run_summary"]["notes"],
        ]
    )
    assert scan(
        public_prose,
        tuple(
            pair for pair in _DNSBLOCK_PREDICATES if pair[0] != "history_seconds"
        ),
    ) == []


def test_transaction_separator_seed_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    findings, inputs = _controlled_syslog_transaction()
    assert premise_holds(inputs, _TEXT_PREDICATES) == []
    clean = render_report_html(findings, _summary(), verbose_level=2)
    _assert_transaction_separators(clean)

    original = html_output._render_transaction_member_line

    def seeded(member: object) -> str:
        rendered = original(member)
        title = member.get("title", "") if isinstance(member, dict) else member
        return rendered.replace("</div>", f" · {escape(str(title), quote=True)}</div>", 1)

    monkeypatch.setattr(html_output, "_render_transaction_member_line", seeded)
    mutated = render_report_html(findings, _summary(), verbose_level=2)
    with pytest.raises(AssertionError):
        _assert_transaction_separators(mutated)


def test_digest_and_blob_renderers_have_clean_vocabulary() -> None:
    digest = _digest_card(
        schema="conn",
        source_name="archive.example",
        zone1_extras=[("hosts", "4")],
        insights=["stable profile"],
        fields=[],
    )
    digest_inputs = ("conn", "archive.example", "hosts", "stable profile")
    assert premise_holds(digest_inputs, _TEXT_PREDICATES) == []
    digest_text = _render_digest(digest)
    assert digest_text
    assert scan(digest_text, _TEXT_PREDICATES) == []

    blob = _text_blob_card(shape_guess="freeform text")
    blob_inputs = (
        "mystery.txt",
        "freeform text",
        "varied",
        "level",
        "ts",
        "msg",
        "service",
        "trace_id",
    )
    assert premise_holds(blob_inputs, _TEXT_PREDICATES) == []
    blob_text = _render_blob(blob)
    assert blob_text
    assert scan(blob_text, _TEXT_PREDICATES) == []


def test_data_bearing_controls_are_ineligible_and_lossless() -> None:
    phrase = "D20 member finding needle remains verbatim"

    assert premise_holds((phrase,), _ERA_PREDICATES) == [
        "D-code",
        "member finding",
        "needle",
    ]
    era_text = render_text_report(
        (EraCard("1. controlled", (("source", phrase),)),), family="zeek"
    )
    assert phrase in era_text

    findings, _inputs = _controlled_syslog_transaction()
    controlled_findings = copy.deepcopy(findings)
    member = controlled_findings[0].evidence["members"][0]
    member["title"] = phrase
    member["sample_raw"] = [phrase]
    assert premise_holds((phrase,), _TEXT_PREDICATES) == ["member finding", "needle"]
    assert phrase in _render_findings_text(controlled_findings, 1)
    parsed = _parse_html(render_report_html(controlled_findings, _summary(), verbose_level=2))
    assert phrase in " ".join(parsed.visible)

    digest = _digest_card(source_name=phrase)
    assert premise_holds((phrase,), _TEXT_PREDICATES) == ["member finding", "needle"]
    assert phrase in _render_digest(digest)

    blob = _text_blob_card(shape_guess=phrase)
    assert premise_holds((phrase,), _TEXT_PREDICATES) == ["member finding", "needle"]
    assert phrase in _render_blob(blob)
