"""PDF handler - the HTML twin via WeasyPrint, with a lazy, testable import seam."""

from __future__ import annotations

import io
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import sigwood.outputs.pdf as pdf_mod
from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.common.output import OutputHandler, get_handler, register_builtin_handlers
from sigwood.outputs.pdf import (
    PdfHandler,
    _PDF_NATIVE_ERROR_BASE,
    _PDF_NATIVE_HINT_OTHER,
    _PDF_NATIVE_HINTS,
    _PDF_PIP_ERROR,
    _native_hint,
    _stack_error,
)


def _native_error() -> str:
    """The OSError-arm message for the CURRENT platform (what end()/preflight
    raise here)."""
    return _PDF_NATIVE_ERROR_BASE.format(hint=_native_hint())

_W = (
    datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
    datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
)


def _summary() -> RunSummary:
    return RunSummary(
        data_window=_W, record_counts={"conn*.log*": 1}, data_size_bytes=10,
        detectors_run=["beacon"], detectors_skipped={},
    )


def _finding() -> Finding:
    return Finding(
        detector="beacon", severity=Severity.HIGH,
        title="192.0.2.10 → 192.0.2.20:443/tcp", description="A regular beat.",
        evidence={"beacon_score": 0.61}, next_steps=["Inspect the flow"],
        ts_generated=datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc), data_window=_W,
    )


def _handler(path: Path) -> PdfHandler:
    h = PdfHandler(output_path=path, verbose_level=0)
    h.begin(_summary())
    h.write([_finding()])
    return h


def _weasyprint_usable(tmp_path: Path) -> bool:
    """The full stack (Python package AND native Pango/cairo) is usable iff a
    tiny write_pdf succeeds. importorskip alone can't catch an OSError-on-use."""
    try:
        import weasyprint  # noqa: F401
        weasyprint.HTML(string="<p>ok</p>").write_pdf(str(tmp_path / "probe.pdf"))
    except (ImportError, OSError):
        return False
    return True


# ── registration is independent of the optional stack (lazy import) ──────────
def test_pdf_registers_without_the_optional_stack() -> None:
    register_builtin_handlers()
    assert get_handler("pdf") is PdfHandler  # importable + registered regardless


# ── the two failure modes both translate to the actionable ValueError ────────
def test_missing_python_package_raises_actionable_error(tmp_path, monkeypatch) -> None:
    def _boom():
        raise ImportError("No module named 'weasyprint'")

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", _boom)
    h = _handler(tmp_path / "r.pdf")
    with pytest.raises(ValueError) as exc:
        h.end()
    # ImportError arm → the pip-extra-only message (no Pango).
    assert str(exc.value) == _PDF_PIP_ERROR
    assert isinstance(exc.value.__cause__, ImportError)


def test_missing_native_library_raises_actionable_error(tmp_path, monkeypatch) -> None:
    # The native Pango/cairo load fails INSIDE the render (returning bytes),
    # which is inside the stack-error translation.
    def _boom(html_str):
        raise OSError("cannot load library 'libpango-1.0-0'")

    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", _boom)
    h = _handler(tmp_path / "r.pdf")
    with pytest.raises(ValueError) as exc:
        h.end()
    # OSError arm → the native-libraries message (names Pango/HarfBuzz/fontconfig
    # + a platform hint), NEVER the pip-only message.
    assert str(exc.value) == _native_error()
    assert str(exc.value) != _PDF_PIP_ERROR
    assert isinstance(exc.value.__cause__, OSError)


def test_write_failure_is_io_error_not_dependency_error(tmp_path, monkeypatch) -> None:
    """A genuine file-write OSError (unwritable path) must surface as its own
    actionable error - NOT mislabeled as a missing-dependency stack error, and
    NOT a raw traceback."""
    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", lambda html_str: b"%PDF-x")
    blocker = tmp_path / "afile"
    blocker.write_text("not a dir", encoding="utf-8")
    target = blocker / "sub" / "r.pdf"  # parent can't be created - ancestor is a file
    h = _handler(target)
    with pytest.raises(ValueError) as exc:
        h.end()
    # A genuine write failure is its OWN message - neither stack-error arm.
    assert str(exc.value) != _PDF_PIP_ERROR
    assert str(exc.value) != _native_error()
    assert "could not write pdf" in str(exc.value)
    assert isinstance(exc.value.__cause__, OSError)


# ── happy-path wiring is testable WITHOUT the native stack ───────────────────
def test_renders_html_twin_and_writes_to_path(tmp_path, monkeypatch) -> None:
    recorded: dict = {}

    def _fake_bytes(html_str):
        recorded["html"] = html_str
        return b"%PDF-fake"

    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", _fake_bytes)
    target = tmp_path / "r.pdf"
    _handler(target).end()
    # the PDF is rendered from the SAME html renderer as the html format,
    # and the returned bytes are written to the target file.
    assert '<span class="brand">sigwood</span>' in recorded["html"]
    assert "threat hunt" in recorded["html"]
    assert "findings-table" in recorded["html"]      # the per-detector table
    # the beacon row via project_row: the score datum renders ONCE - bare in the
    # cell, labeled by its <th> header, never double-labeled `score=…` (D-8).
    assert ">score</th>" in recorded["html"]         # the column header carries the label
    assert ">0.610</td>" in recorded["html"]         # the cell shows the bare datum
    assert "score=0.610" not in recorded["html"]     # not double-labeled
    assert target.read_bytes() == b"%PDF-fake"


# ── preflight: fail-fast probe of the WeasyPrint/Pango stack ─────────────────
def test_base_preflight_is_noop() -> None:
    """Non-pdf handlers inherit the base no-op preflight."""
    assert OutputHandler.preflight() is None
    assert get_handler("text").preflight() is None
    assert get_handler("html").preflight() is None


def test_pdf_preflight_missing_python_package_raises(monkeypatch) -> None:
    def _boom():
        raise ImportError("No module named 'weasyprint'")

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", _boom)
    with pytest.raises(ValueError) as exc:
        PdfHandler.preflight()
    assert str(exc.value) == _PDF_PIP_ERROR  # preflight shares the split translation
    assert isinstance(exc.value.__cause__, ImportError)


def test_pdf_preflight_missing_native_library_raises(monkeypatch) -> None:
    def _boom(html_str):
        raise OSError("cannot load library 'libpango-1.0-0'")

    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", _boom)
    with pytest.raises(ValueError) as exc:
        PdfHandler.preflight()
    assert str(exc.value) == _native_error()
    assert isinstance(exc.value.__cause__, OSError)


# ── the split translation: platform-forked native hint + voice ───────────────
@pytest.mark.parametrize(
    "platform, needle",
    [
        ("darwin", "brew install pango"),
        ("linux", "apt install libpango-1.0-0"),
        ("linux", "dnf install pango"),
        ("win32", _PDF_NATIVE_HINT_OTHER),
    ],
)
def test_native_hint_is_platform_forked(monkeypatch, platform, needle) -> None:
    """The OSError arm names the right install command per sys.platform; an
    unrecognised platform points at the README (no manager guessed)."""
    monkeypatch.setattr(sys, "platform", platform)
    msg = _stack_error(OSError("cannot load library 'libpango-1.0-0'"))
    assert needle in msg
    # darwin must NOT carry an apt/dnf hint and vice-versa (no cross-platform leak).
    if platform == "darwin":
        assert "apt install" not in msg and "dnf install" not in msg
    if platform == "win32":
        assert "brew" not in msg and "apt install" not in msg


def test_native_hint_other_for_unknown_platform(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "sunos5")
    assert _native_hint() == _PDF_NATIVE_HINT_OTHER


def test_stack_error_strings_follow_voice() -> None:
    """VOICE: lowercase-led, raised bare (no `sigwood:` self-prefix), no
    decorative `Warning:`; the pip extra is quoted for shell safety and uses the
    owned `- run:` actionable tail; single clause → no terminal period."""
    msgs = [_PDF_PIP_ERROR, _stack_error(OSError("x"))]
    for m in msgs:
        assert m[0].islower()  # lowercase-led
        assert not m.startswith("sigwood")  # cli.main owns the prefix
        assert "Warning:" not in m  # no decorative prefix
        assert not m.rstrip().endswith(".")  # single clause / em-dash tail
    assert "- run: pip install 'sigwood[pdf]'" in _PDF_PIP_ERROR  # quoted extra
    assert "Pango" not in _PDF_PIP_ERROR  # pip arm names ONLY the extra, no Pango


def test_pdf_preflight_passes_when_stack_usable(monkeypatch) -> None:
    """A usable stack → preflight returns cleanly (no raise)."""
    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", lambda html_str: b"%PDF-fake")
    assert PdfHandler.preflight() is None


def test_pdf_handler_requires_a_target() -> None:
    """A bare construction (neither stream nor output_path) is a caller misuse -
    fail fast at construction with an actionable error, never a raw AttributeError
    in end(); pdf must never silently default to a stream (binary-safety)."""
    with pytest.raises(ValueError, match="requires a stream or an output_path"):
        PdfHandler()


# ── pipe stream mode - bytes to a binary stream, no file ─────────────────────
def test_pdf_stream_mode_writes_bytes_to_pipe(monkeypatch) -> None:
    """PdfHandler(stream=<binary>) renders to the stream (sys.stdout.buffer on a
    pipe), never a file."""
    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", lambda html_str: b"%PDF-fake")
    buf = io.BytesIO()
    h = PdfHandler(stream=buf, verbose_level=0)
    h.begin(_summary())
    h.write([_finding()])
    h.end()
    assert buf.getvalue() == b"%PDF-fake"


# ── real end-to-end, only when the full stack is installed ───────────────────
def test_real_pdf_starts_with_magic(tmp_path) -> None:
    if not _weasyprint_usable(tmp_path):
        pytest.skip("WeasyPrint/Pango stack not installed")
    target = tmp_path / "real.pdf"
    _handler(target).end()
    assert target.read_bytes()[:4] == b"%PDF"
