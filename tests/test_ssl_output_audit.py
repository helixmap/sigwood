"""Adversarial output audit for the ssl surfaces.

Every ssl value that reaches a sink is attacker-derivable: `validation_status`
and the tuple members come from the wire, and the addresses come from the log.
This traces them to the terminal, spreadsheet, markup and machine sinks and
asserts each one neutralizes at its own seam. Addresses are RFC 5737 space.
"""

from __future__ import annotations

import csv
import io
import json
from copy import deepcopy
from datetime import datetime, timezone

import pandas as pd

from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs.html import HtmlHandler
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler

WINDOW = (
    datetime(2026, 8, 1, tzinfo=timezone.utc),
    datetime(2026, 8, 8, tzinfo=timezone.utc),
)

# One token per injection class, all reachable from a TLS handshake or a log
# line: terminal control + single-byte CSI, spreadsheet formula lead, markup,
# shell metacharacters, command substitution, an embedded NEWLINE (which can
# forge a second row in a line-oriented surface), and a LEADING DASH (which a
# shell reads as an option rather than an operand).
HOSTILE_STATUS = (
    "=cmd|'/c calc'!A1\x1b[31m<script>alert(1)</script>\x9b2K"
    "; rm -rf / $(id) `whoami`\nseverity,detector,forged"
)
HOSTILE_TUPLE = (
    "TLSv12|\x00\x1b]0;pwned\x07<img src=x onerror=alert(1)>|x25519|"
    "--output=/etc/passwd"
)
SRC = "192.0.2.10"
DST = "198.51.100.20"


def _finding() -> Finding:
    return Finding(
        detector="ssl",
        severity=Severity.MEDIUM,
        title=f"{SRC} → {DST}",
        description="A session did not validate.",
        evidence={
            "src": SRC,
            "dst": DST,
            "severity_basis": ["sni_absent", "validation"],
            "conn_count": 4,
            "validation_status": HOSTILE_STATUS,
            "validation_mix": {HOSTILE_STATUS: 4},
            "tuple": HOSTILE_TUPLE,
            "tuple_share": 0.01,
            "tls_versions": {"TLSv12": 4},
            "port_mix": "443 (4)",
            "first_seen": "2026-08-01T00:00:00+00:00",
            "cert_visible_share": 1.0,
        },
        next_steps=["Identify the local host"],
        ts_generated=datetime(2026, 8, 8, tzinfo=timezone.utc),
        data_window=WINDOW,
    )


def _summary() -> RunSummary:
    return RunSummary(
        data_window=WINDOW,
        record_counts={"ssl*.log*": 4},
        data_size_bytes=1024,
        detectors_run=["ssl"],
        detectors_skipped={},
        detector_missions={"ssl": "Mission for ssl."},
        notes=["ssl: a server certificate was visible on 4 of 4 outbound sessions (100%)"],
    )


def _render_finding(handler_cls, finding: Finding, *, level: int = 2, **kw) -> str:
    stream = io.StringIO()
    handler = handler_cls(stream=stream, verbose_level=level, **kw)
    handler.begin(_summary())
    handler.write([finding])
    handler.end()
    return stream.getvalue()


def _render(handler_cls, **kw) -> str:
    return _render_finding(handler_cls, _finding(), **kw)


_CONTROL = ("\x1b", "\x9b", "\x00", "\x07")


def test_text_strips_every_control_byte_from_ssl_values() -> None:
    out = _render(TextHandler, max_findings_per_detector=100)
    for byte in _CONTROL:
        assert byte not in out
    # The row must SURVIVE, or every assertion above passes on an empty page.
    assert SRC in out and DST in out
    # The neutralized remainder still renders - stripping is not dropping.
    assert "rm -rf /" in out and "$(id)" in out


def test_html_escapes_markup_and_strips_controls() -> None:
    out = _render(HtmlHandler, max_findings_per_detector=100)
    for byte in _CONTROL:
        assert byte not in out
    assert SRC in out and DST in out
    assert "<script>alert(1)</script>" not in out
    assert "<img src=x onerror=alert(1)>" not in out
    assert "&lt;script&gt;" in out


def test_pdf_receives_the_same_neutralized_markup(monkeypatch) -> None:
    """pdf IS html through one renderer, so the audit must inspect the markup
    handed to the pdf seam. The native stack is optional and absent here; the
    seam is patched so the contract is still traced rather than skipped."""
    from sigwood.outputs import pdf as pdf_mod

    captured: dict[str, str] = {}

    def _fake(html_str: str) -> bytes:
        captured["html"] = html_str
        return b"%PDF-ssl-audit"

    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", _fake)
    sink = io.BytesIO()
    handler = pdf_mod.PdfHandler(stream=sink, verbose_level=2,
                                 max_findings_per_detector=100)
    handler.begin(_summary())
    handler.write([_finding()])
    handler.end()

    assert sink.getvalue() == b"%PDF-ssl-audit"
    html = captured["html"]
    for byte in _CONTROL:
        assert byte not in html
    assert SRC in html and DST in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_csv_guards_the_formula_lead_and_strips_controls() -> None:
    out = _render(CsvHandler)
    for byte in _CONTROL:
        assert byte not in out
    rows = list(csv.reader(io.StringIO(out)))
    header, body = rows[0], [r for r in rows[1:] if r]
    assert body, "the worklist rendered no ssl row"
    for cell in body[0]:
        assert not cell.startswith(("=", "+", "-", "@", "\t", "\r")), (
            f"an unguarded formula lead reaches a spreadsheet: {cell!r}"
        )
    assert any("cmd" in cell for cell in body[0]), "the guarded value was dropped, not quoted"
    # Row identity survives, and the embedded newline stayed INSIDE its quoted
    # cell instead of forging a second record with a fabricated header.
    joined = " ".join(body[0])
    assert SRC in joined and DST in joined
    assert all(r[0] in ("", "medium") for r in body), "a newline forged a row"
    assert len(body[0]) == len(header)


def test_json_stays_valid_and_lossless() -> None:
    """json is the lossless surface: controls are escaped by the encoder, not
    removed, so a consumer can still see exactly what the wire carried."""
    out = _render(JsonHandler)
    payload = json.loads(out)
    finding = payload["findings"][0]
    assert finding["evidence"]["validation_status"] == HOSTILE_STATUS
    assert finding["evidence"]["tuple"] == HOSTILE_TUPLE
    assert finding["evidence"]["src"] == SRC
    assert finding["evidence"]["dst"] == DST
    assert "\x1b" not in out and "\\u001b" in out


def test_human_rendering_cannot_mutate_machine_bytes_or_source_evidence() -> None:
    finding = _finding()
    frozen_evidence = deepcopy(finding.evidence)
    json_before = _render_finding(JsonHandler, finding)
    csv_before = _render_finding(CsvHandler, finding)

    for level in (1, 2):
        text = _render_finding(
            TextHandler,
            finding,
            level=level,
            max_findings_per_detector=100,
        )
        html = _render_finding(
            HtmlHandler,
            finding,
            level=level,
            max_findings_per_detector=100,
        )
        assert SRC in text and DST in text
        assert SRC in html and DST in html

    assert finding.evidence == frozen_evidence
    assert _render_finding(JsonHandler, finding) == json_before
    assert _render_finding(CsvHandler, finding) == csv_before


def test_the_rendered_note_carries_counts_and_no_log_derived_value() -> None:
    """The visibility note is counts only. Checked on the text that actually
    reaches a sink, because a helper verified in isolation says nothing about
    what a renderer did with its return value."""
    summary = RunSummary(
        data_window=WINDOW,
        record_counts={"ssl*.log*": 4},
        data_size_bytes=1024,
        detectors_run=["ssl"],
        detectors_skipped={},
        detector_missions={"ssl": "Mission for ssl."},
        notes=[
            "ssl: a server certificate was visible on 1 of 4 outbound sessions "
            "(25%) - the validation leg covers only those"
        ],
    )
    stream = io.StringIO()
    handler = TextHandler(stream=stream, verbose_level=0, max_findings_per_detector=100)
    handler.begin(summary)
    handler.write([])
    handler.end()
    out = stream.getvalue()

    assert "1 of 4 outbound sessions" in out
    for identity in ("192.0.2.10", "198.51.100.20", HOSTILE_STATUS, HOSTILE_TUPLE):
        assert identity not in out
