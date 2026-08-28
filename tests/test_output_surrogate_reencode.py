"""Output surfaces must not re-encode a surrogate-escaped filesystem byte to a raw
terminal control byte on a surrogateescape-configured stream.

``os.fsdecode`` maps a non-UTF-8 filename byte (0x80-0xFF) to a lone surrogate
(U+DC80-U+DCFF). Left in a rendered value, that surrogate survives to the stream
write and, on a stream opened ``errors="surrogateescape"`` (a CPython default under
UTF-8 mode), re-encodes to the original raw byte (e.g. U+DC9B -> 0x9b, the single-byte
C1 CSI): a live control-byte injection on text / csv / html.

A real hostile filename carrying a raw high byte is rejected by APFS on macOS
(``Errno 92``), so these tests drive the output seam with a directly-constructed
lone-surrogate string standing in for ``os.fsdecode(b"host\\x9bevil")``. The bug only
reproduces through a real re-encode seam, so each surface renders through its actual
handler into an ``io.TextIOWrapper`` over ``io.BytesIO`` with ``errors="surrogateescape"``.
The raw bytes are checked by decoding them back with the same ``surrogateescape`` policy:
a re-encoded surrogate byte round-trips to a U+DC80-U+DCFF code point, while a legitimate
multibyte glyph (box rules, arrows in the banner) is valid UTF-8 and never does. A plain
0x80-0x9f byte scan would false-positive on those glyphs' UTF-8 continuation bytes.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs.html import HtmlHandler
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler

# os.fsdecode(b"host\x9bevil") maps the 0x9b byte to the lone surrogate U+DC9B.
_SURROGATE = "host\udc9bevil"
_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _surrogateescape_stream() -> tuple[io.BytesIO, io.TextIOWrapper]:
    buf = io.BytesIO()
    return buf, io.TextIOWrapper(buf, encoding="utf-8", errors="surrogateescape", newline="")


def _assert_no_reencoded_surrogate(raw: bytes) -> None:
    decoded = raw.decode("utf-8", errors="surrogateescape")
    offenders = [c for c in decoded if 0xDC80 <= ord(c) <= 0xDCFF]
    assert not offenders, f"surrogate-escaped byte re-encoded into output: {offenders!r}"


def _finding() -> Finding:
    # "probe" is projector-less, so its title routes through the generic
    # _render_finding / _esc / csv-cell path: the filename-derived value seam.
    return Finding(
        detector="probe",
        severity=Severity.INFO,
        title=_SURROGATE,
        description="",
        evidence={},
        next_steps=[],
        ts_generated=_NOW,
        data_window=(_NOW, _NOW),
    )


def _run_summary() -> RunSummary:
    return RunSummary(
        data_window=(_NOW, _NOW),
        record_counts={},
        data_size_bytes=0,
        detectors_run=["probe"],
        detectors_skipped={},
        detector_missions={"probe": "Mission for probe."},
    )


def test_text_handler_no_surrogate_reencode() -> None:
    buf, stream = _surrogateescape_stream()
    handler = TextHandler(stream=stream)
    handler.begin(_run_summary())
    handler.write([_finding()])
    handler.end()
    stream.flush()
    _assert_no_reencoded_surrogate(buf.getvalue())


def test_html_handler_no_surrogate_reencode() -> None:
    buf, stream = _surrogateescape_stream()
    handler = HtmlHandler(stream=stream)
    handler.begin(_run_summary())
    handler.write([_finding()])
    handler.end()
    stream.flush()
    _assert_no_reencoded_surrogate(buf.getvalue())


def test_csv_handler_no_surrogate_reencode() -> None:
    buf, stream = _surrogateescape_stream()
    handler = CsvHandler(stream=stream)
    handler.begin(_run_summary())
    handler.write([_finding()])
    # CsvHandler.end() reconfigures the stream's newline handling before it writes;
    # nothing is written to the stream before end(), so that reconfigure succeeds.
    handler.end()
    stream.flush()
    _assert_no_reencoded_surrogate(buf.getvalue())


def test_json_handler_escapes_surrogate() -> None:
    # json is not on the strip path: its safety comes from json.dump's default
    # ensure_ascii=True, which escapes the surrogate to ASCII text. Pinned through
    # the real handler so the contract is visible if that default ever changes.
    sink = io.StringIO()
    handler = JsonHandler(stream=sink)
    handler.begin(_run_summary())
    handler.write([_finding()])
    handler.end()
    out = sink.getvalue()
    assert out.isascii(), "json emitted a non-ASCII char (ensure_ascii regressed)"
    assert "udc9b" in out, "surrogate lost from the lossless json feed"
