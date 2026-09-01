"""dnsblock reading projections, output split, and semantic digest."""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import math
from datetime import datetime, timezone

import numpy as np

import sigwood.outputs.pdf as pdf_output
from sigwood.common.display import version_string
from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.outputs._evidence import curated_evidence
from sigwood.outputs._render_model import (
    Section,
    _build_renderable,
    _dnsblock_history,
    html_columns,
    project_row,
    text_columns,
)
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs.html import HtmlHandler
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.pdf import PdfHandler
from sigwood.outputs.text import TextHandler


_W = (
    datetime(2026, 1, 1, tzinfo=timezone.utc),
    datetime(2026, 1, 8, tzinfo=timezone.utc),
)


def _finding(kind: str, **evidence: object) -> Finding:
    base: dict[str, object] = {"kind": kind}
    base.update(evidence)
    return Finding(
        detector="dnsblock",
        severity=Severity.INFO if kind.endswith("activity") or kind.startswith("prior") else Severity.LOW,
        title={
            "recurring_activity": "recurring blocked-name activity",
            "prior_handling_exclusions": "names withheld from novelty because Pi-hole logged earlier handling",
        }.get(kind, str(evidence.get("address", "192.0.2.7"))),
        description="measured dnsblock activity",
        evidence=base,
        next_steps=[],
        ts_generated=_W[1],
        data_window=_W,
    )


def _summary() -> RunSummary:
    return RunSummary(
        data_window=_W,
        record_counts={"pihole": 1},
        data_size_bytes=42,
        detectors_run=["dnsblock"],
        detectors_skipped={},
        detector_missions={"dnsblock": "Mission for dnsblock."},
        generated_at=_W[1],
    )


def test_recurring_visibility_matrix_is_output_owned_and_counts_are_pre_cap() -> None:
    recurring = _finding("recurring_activity", pair_count=2)
    prior = _finding("prior_handling_exclusions", withheld_name_count=1)
    assert _build_renderable("dnsblock", [recurring], 0, 100).level_visible_total == 0
    assert _build_renderable("dnsblock", [recurring], 1, 100).level_visible_total == 1
    assert _build_renderable("dnsblock", [recurring], 2, 100).level_visible_total == 1

    arrival = _finding(
        "arrival",
        address="192.0.2.7",
        family_key="example.test",
        coverage_lane="strong",
        first_associated_period="2026-01-02T00:00:00+00:00",
    )
    for level in (0, 1, 2):
        rendered = _build_renderable("dnsblock", [recurring, arrival], level, 100)
        assert rendered.level_visible_total == 2
        assert rendered.severity_breakdown == {Severity.INFO: 1, Severity.LOW: 1}

    assert _build_renderable("dnsblock", [prior, recurring], 0, 100).level_visible_total == 1


def test_context_rows_are_last_full_width_and_outside_the_cap_budget() -> None:
    arrivals = [
        _finding(
            "arrival",
            address=f"192.0.2.{number}",
            family_key=f"f{number}.test",
            first_associated_period=f"2026-01-0{number}T00:00:00+00:00",
        )
        for number in (3, 2, 1)
    ]
    prior = _finding("prior_handling_exclusions")
    recurring = _finding("recurring_activity")
    rendered = _build_renderable(
        "dnsblock", [recurring, *arrivals, prior], 0, 1
    )
    assert [section.label for section in rendered.sections] == ["first activity", "context"]
    assert rendered.cap_truncated == 2
    assert [f.evidence["kind"] for f in rendered.sections[-1].findings] == [
        "prior_handling_exclusions",
        "recurring_activity",
    ]
    assert all(project_row(f)[0].full_width for f in rendered.sections[-1].findings)


def test_unknown_kind_is_preserved_in_a_trailing_full_width_section() -> None:
    unknown = _finding("future_shape", address="192.0.2.9")
    arrival = _finding(
        "arrival",
        address="192.0.2.7",
        first_associated_period="2026-01-02T00:00:00+00:00",
    )
    rendered = _build_renderable("dnsblock", [unknown, arrival], 0, 100)
    assert [section.label for section in rendered.sections] == ["first activity", "other"]
    assert rendered.sections[-1].findings == [unknown]
    assert project_row(unknown)[0].full_width


def test_dnsblock_headline_projection_formats_exact_sufficient_statistics() -> None:
    arrival = _finding(
        "arrival",
        address="192.0.2.7",
        family_key="example.test",
        qualifying_name_count=3,
        attributed_query_count=12,
        active_periods=2,
        eligible_periods=5,
        first_associated_period="2026-01-02T00:00:00+00:00",
        prior_other_address_count=100,
        prior_other_address_count_at_cap=True,
    )
    assert [cell.value for cell in project_row(arrival)][-1] == (
        "100+ other addresses queried it"
    )

    burst = _finding(
        "burst",
        address="192.0.2.7",
        family_key="example.test",
        coverage_lane="strong",
        peak_count=25,
        baseline_median_twice=5,
        active_periods=4,
        eligible_periods=5,
        attributed_query_count=40,
    )
    values = [cell.value for cell in project_row(burst)]
    assert "median=2.5" in values
    assert "10×" in values

    burst.evidence["peak_count"] = 13
    burst.evidence["baseline_median_twice"] = 6
    assert "13/3×" in [cell.value for cell in project_row(burst)]

    unavailable = copy.deepcopy(burst)
    unavailable.evidence["baseline_median_twice"] = 0
    assert "multiplier unavailable" in [cell.value for cell in project_row(unavailable)]


def _render_reading(handler_type, findings: list[Finding]) -> str:
    stream = io.StringIO()
    handler = handler_type(stream=stream)
    handler.begin(_summary())
    handler.write(findings)
    handler.end()
    return stream.getvalue()


def _arrival_with_history(value: object = 86_400.0) -> Finding:
    return _finding(
        "arrival",
        address="192.0.2.7",
        family_key="example.test",
        coverage_lane="strong",
        qualifying_name_count=2,
        attributed_query_count=6,
        active_periods=2,
        eligible_periods=5,
        first_associated_period="2026-01-02T00:00:00+00:00",
        history_seconds=value,
        prior_other_address_count=0,
        prior_other_address_count_at_cap=False,
    )


def test_dnsblock_history_has_a_closed_never_raising_domain() -> None:
    rejected = [True, "21", None, math.nan, math.inf, -1]
    assert [_dnsblock_history(value) for value in rejected] == [""] * len(rejected)
    assert _dnsblock_history(np.int64(86_400)) == "over 1d"
    assert _dnsblock_history(3_600.0) == "over 1h"
    assert _dnsblock_history(0.0) == "over 0s"


def test_dnsblock_history_column_is_fixed_and_section_pruning_stays_aligned() -> None:
    current = _arrival_with_history()
    legacy = copy.deepcopy(current)
    legacy.evidence.pop("history_seconds")
    fold = _finding(
        "arrival_fold",
        address="192.0.2.8",
        member_count=4,
        earliest_first_associated_period="2026-01-02T00:00:00+00:00",
        history_seconds=86_400.0,
    )

    assert [cell.key for cell in project_row(current)][-3:] == [
        "first", "history", "prior"
    ]
    assert [cell.key for cell in project_row(legacy)][-3:] == [
        "first", "history", "prior"
    ]
    assert project_row(legacy)[-2].value == ""
    assert [cell.key for cell in project_row(fold)][-2:] == ["first", "history"]

    legacy_section = Section("first activity", [legacy], 1)
    mixed_section = Section("first activity", [legacy, current], 2)
    current_section = Section("first activity", [current], 1)
    assert [column.key for column in text_columns(legacy_section)] == [
        None, "names", "queries", "days", "first", "prior"
    ]
    assert [column.key for column in text_columns(mixed_section)][-3:] == [
        "first", "history", "prior"
    ]
    assert [column.key for column in text_columns(current_section)][-3:] == [
        "first", "history", "prior"
    ]
    assert [column.key for _, column in html_columns(legacy_section)] == [
        None, "names", "queries", "days", "first", "prior"
    ]
    assert [column.key for _, column in html_columns(mixed_section)][-3:] == [
        "first", "history", "prior"
    ]

    for handler_type in (TextHandler, HtmlHandler):
        all_current = _render_reading(handler_type, [current])
        mixed = _render_reading(handler_type, [legacy, current])
        assert "over 1d" in all_current
        assert mixed.count("over 1d") == 1


def test_legacy_dnsblock_reading_bytes_pin_the_reviewed_mission_chrome(pin_tz) -> None:
    legacy = _arrival_with_history()
    legacy.title = "192.0.2.7"
    legacy.evidence.pop("history_seconds")
    expected = {
        TextHandler: "3c1347a2c142d609c9b9f109e5fa96cf8196538ab5f9449239c5b3b6c88abcc4",
        HtmlHandler: "0712f416763064c8684b02b25f8e89bf1188ab7f9c45ef3e146cfdf80bb3fa6f",
    }
    pin_tz("America/Chicago")
    for handler_type, digest in expected.items():
        # The run-summary banner carries `generated: ... - sigwood <version>`, so the
        # raw bytes move on every release. Normalizing that one token keeps the pin
        # over the rendered surface rather than over the release number.
        rendered = _render_reading(handler_type, [legacy]).replace(
            version_string(), "sigwood <version>"
        )
        assert hashlib.sha256(rendered.encode()).hexdigest() == digest


def test_hostile_dnsblock_history_is_empty_on_real_reading_paths() -> None:
    finding = _arrival_with_history('<script>\x1b"')
    for handler_type in (TextHandler, HtmlHandler):
        rendered = _render_reading(handler_type, [finding])
        assert "history_seconds" not in rendered
        assert "<script>" not in rendered


def test_fold_curated_evidence_has_exact_shares_and_omits_unavailable_ratios() -> None:
    fold = _finding(
        "arrival_fold",
        member_count=4,
        earliest_first_associated_period="2026-01-02T00:00:00+00:00",
        members_omitted=2,
        distinct_report_addresses=3,
        shares_available=True,
        attributed_share_num=3,
        attributed_share_den=7,
        query_share_num=11,
        query_share_den=19,
        gravity_blocked=3,
        regex_blocked=1,
        forwarded=2,
        cached=2,
    )
    curated = curated_evidence(fold)
    assert list(curated)[:4] == [
        "member_count", "attributed_share", "query_share",
        "earliest_first_associated_period",
    ]
    assert curated["members_omitted"] == 2
    assert curated["attributed_share"] == "3/7"
    assert curated["query_share"] == "11/19"
    assert curated["block_ratio"] == 0.5
    assert not {"gravity_blocked", "regex_blocked", "forwarded", "cached"} & curated.keys()

    unavailable = copy.deepcopy(fold)
    unavailable.evidence["shares_available"] = False
    assert "attributed_share" not in curated_evidence(unavailable)
    assert "query_share" not in curated_evidence(unavailable)


def test_entity_curated_evidence_derives_one_ratio_without_mechanism_split() -> None:
    mechanism_keys = {"gravity_blocked", "regex_blocked", "forwarded", "cached"}
    for kind in ("arrival", "burst", "arrival_fold"):
        finding = _finding(
            kind,
            gravity_blocked=2,
            regex_blocked=1,
            forwarded=2,
            cached=1,
        )
        curated = curated_evidence(finding)
        assert curated["block_ratio"] == 0.5
        assert not mechanism_keys & curated.keys()


def test_all_five_handlers_receive_dnsblock_and_keep_machine_surfaces_uncapped(
    monkeypatch,
) -> None:
    arrival = _finding(
        "arrival",
        address="192.0.2.7",
        family_key="example.test",
        qualifying_name_count=2,
        attributed_query_count=6,
        active_periods=2,
        eligible_periods=5,
        first_associated_period="2026-01-02T00:00:00+00:00",
        history_seconds=86_400.0,
        prior_other_address_count=0,
        prior_other_address_count_at_cap=False,
    )
    recurring = _finding("recurring_activity", pair_count=1)
    hostile = '=SUM(1,1)<script>&"\x1b\x7f'
    arrival.title = hostile
    findings = [arrival, recurring]

    text = io.StringIO()
    text_handler = TextHandler(text, max_findings_per_detector=1)
    text_handler.begin(_summary())
    text_handler.write(findings)
    text_handler.end()
    assert "first activity (1)" in text.getvalue()
    assert "recurring blocked-name activity" in text.getvalue()
    assert "over 1d" in text.getvalue()
    assert "\x1b" not in text.getvalue() and "\x7f" not in text.getvalue()

    csv_stream = io.StringIO()
    csv_handler = CsvHandler(csv_stream)
    csv_handler.begin(_summary())
    csv_handler.write(findings)
    csv_handler.end()
    csv_rows = list(csv.DictReader(io.StringIO(csv_stream.getvalue())))
    assert len(csv_rows) == 2
    assert csv_rows[0]["finding"].startswith("'=SUM")
    assert "history_seconds=86400.0" in csv_rows[0]["signals"]
    assert "\x1b" not in csv_stream.getvalue() and "\x7f" not in csv_stream.getvalue()

    json_stream = io.StringIO()
    json_handler = JsonHandler(json_stream)
    json_handler.begin(_summary())
    json_handler.write(findings)
    json_handler.end()
    json_findings = json.loads(json_stream.getvalue())["findings"]
    assert len(json_findings) == 2
    assert json_findings[0]["evidence"]["history_seconds"] == 86_400.0
    assert "\x1b" not in json_stream.getvalue() and "\x7f" not in json_stream.getvalue()

    html_stream = io.StringIO()
    html_handler = HtmlHandler(stream=html_stream, max_findings_per_detector=1)
    html_handler.begin(_summary())
    html_handler.write(findings)
    html_handler.end()
    assert "first activity" in html_stream.getvalue()
    assert "recurring blocked-name activity" in html_stream.getvalue()
    assert "over 1d" in html_stream.getvalue()
    assert "&lt;script&gt;" in html_stream.getvalue()
    assert "\x1b" not in html_stream.getvalue() and "\x7f" not in html_stream.getvalue()

    captured: dict[str, str] = {}

    def render_pdf(source: str) -> bytes:
        captured["html"] = source
        return b"%PDF-reading-projection"

    monkeypatch.setattr(pdf_output, "_render_pdf_bytes", render_pdf)
    pdf_stream = io.BytesIO()
    pdf_handler = PdfHandler(stream=pdf_stream, max_findings_per_detector=1)
    pdf_handler.begin(_summary())
    pdf_handler.write(findings)
    pdf_handler.end()
    assert pdf_stream.getvalue() == b"%PDF-reading-projection"
    assert "recurring blocked-name activity" in captured["html"]
    assert "over 1d" in captured["html"]
    assert "&lt;script&gt;" in captured["html"]
    assert "href" not in captured["html"]
