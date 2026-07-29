"""Shared output control-code stripping contract."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

import pandas as pd

from sigwood.common.finding import RunSummary
from sigwood.detectors.beacon import _make_finding
from sigwood.outputs import pdf as pdf_output
from sigwood.outputs._sanitize import strip_control, strip_control_keep_newlines
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs.html import render_report_html
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler

_CONTROL_CODEPOINTS = (
    tuple(range(0x00, 0x20))
    + (0x7F,)
    + tuple(range(0x80, 0xA0))
)


def test_strip_control_drops_full_control_class() -> None:
    for codepoint in _CONTROL_CODEPOINTS:
        assert strip_control(chr(codepoint)) == ""


def test_strip_control_keep_newlines_preserves_only_newline() -> None:
    for codepoint in _CONTROL_CODEPOINTS:
        expected = "\n" if codepoint == ord("\n") else ""
        assert strip_control_keep_newlines(chr(codepoint)) == expected


def test_control_helpers_drift_only_on_newline() -> None:
    for codepoint in range(0x120):
        value = chr(codepoint)
        if codepoint == ord("\n"):
            assert strip_control(value) == ""
            assert strip_control_keep_newlines(value) == "\n"
        else:
            assert strip_control(value) == strip_control_keep_newlines(value)


def test_non_control_report_glyphs_survive() -> None:
    value = "flow 192.0.2.1 -> 198.51.100.2 -> ▇"
    assert strip_control(value) == value
    assert strip_control_keep_newlines(value) == value


# os.fsdecode maps a non-UTF-8 filename byte (0x80-0xFF) to a lone surrogate in
# U+DC80-U+DCFF; both strip helpers drop the whole range so it cannot re-encode to
# a raw control byte on a surrogateescape output stream.
_SURROGATE_ESCAPE_CODEPOINTS = tuple(range(0xDC80, 0xDD00))


def test_strip_control_drops_surrogate_escape_range() -> None:
    for codepoint in _SURROGATE_ESCAPE_CODEPOINTS:
        char = chr(codepoint)
        assert strip_control(char) == ""
        # No surrogate-escaped byte is a newline, so keep_newlines drops it too.
        assert strip_control_keep_newlines(char) == ""


def test_surrogate_scope_boundaries() -> None:
    # Stripped: the surrogateescape byte range only. U+DCA0 (byte 0xA0) proves the
    # range is not narrowed to the C1 subset U+DC80-U+DC9F.
    for codepoint in (0xDC80, 0xDC9B, 0xDCA0, 0xDCFF):
        assert strip_control(chr(codepoint)) == ""
        assert strip_control_keep_newlines(chr(codepoint)) == ""
    # Survive: outside the surrogateescape byte range. U+DC7F / U+DD00 bracket the
    # range; U+D800 is a high surrogate. Guards against broad surrogate erasure.
    for codepoint in (0xDC7F, 0xDD00, 0xD800):
        assert strip_control(chr(codepoint)) == chr(codepoint)
        assert strip_control_keep_newlines(chr(codepoint)) == chr(codepoint)


def test_beacon_hostile_destination_loses_command_sink_and_renders_inert() -> None:
    """Beacon's log-controlled destination stays data across every report sink."""
    window = (
        datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
        datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc),
    )
    controls = "".join(
        chr(codepoint) for codepoint in _CONTROL_CODEPOINTS
        if codepoint != ord("\n")
    )
    destination = "=DST_LEFT'" + controls + "DST_RIGHT"
    finding = _make_finding(
        "192.0.2.10",
        destination,
        443,
        "tcp",
        {
            "beacon_score": 0.61,
            "dominant_period": 600.0,
            "dominant_period_m": 10.0,
            "spectral_ratio": 0.1,
            "prominence": 50.0,
            "prominence_norm": 0.5,
            "jitter_cv": 0.1,
            "conn_count": 144,
            "occupancy": 0.1,
        },
        pd.DataFrame({"bytes": [512]}),
        window,
    )
    assert all("zeek-cut" not in step for step in finding.next_steps)

    summary = RunSummary(
        data_window=window,
        record_counts={"conn*.log*": 144},
        data_size_bytes=0,
        detectors_run=["beacon"],
        detectors_skipped={},
    )
    sanitized_destination = "=DST_LEFT'DST_RIGHT"

    text_stream = io.StringIO()
    TextHandler(stream=text_stream, verbose_level=1).write([finding])
    text_report = text_stream.getvalue()
    assert strip_control_keep_newlines(text_report) == text_report
    assert sanitized_destination in text_report
    assert "zeek-cut" not in text_report

    csv_stream = io.StringIO()
    csv_handler = CsvHandler(stream=csv_stream, verbose_level=1)
    csv_handler.begin(summary)
    csv_handler.write([finding])
    csv_handler.end()
    csv_row = next(csv.DictReader(io.StringIO(csv_stream.getvalue())))
    expected_steps = "\n".join(strip_control(step) for step in finding.next_steps)
    assert csv_row["next_steps"] == expected_steps
    assert csv_row["next_steps"].count("\n") == len(finding.next_steps) - 1
    assert csv_row["next_steps"][0] not in "=+-@\t\r"
    assert sanitized_destination in csv_row["next_steps"]
    assert "zeek-cut" not in csv_row["next_steps"]

    html_report = render_report_html(
        [finding],
        summary,
        verbose_level=1,
        max_findings_per_detector=100,
    )
    assert strip_control_keep_newlines(html_report) == html_report
    assert "=DST_LEFT&#x27;DST_RIGHT" in html_report
    assert "zeek-cut" not in html_report
    # PDF owns no second finding renderer; it consumes this exact escaped HTML seam.
    assert pdf_output.render_report_html is render_report_html

    json_stream = io.StringIO()
    json_handler = JsonHandler(stream=json_stream, verbose_level=1)
    json_handler.begin(summary)
    json_handler.write([finding])
    json_handler.end()
    raw_json = json_stream.getvalue()
    assert strip_control_keep_newlines(raw_json) == raw_json
    parsed_steps = json.loads(raw_json)["findings"][0]["next_steps"]
    assert parsed_steps == finding.next_steps
    assert "zeek-cut" not in "\n".join(parsed_steps)
