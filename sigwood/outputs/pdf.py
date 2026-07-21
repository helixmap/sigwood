"""PDF output handler - the HTML twin rendered through WeasyPrint.

``pdf`` is ``html`` rendered to PDF by WeasyPrint: ONE renderer, two outputs
(``render_report_html`` is reused verbatim). PDF is never a second report shape.

The WeasyPrint import is LAZY (no module-level ``import weasyprint``) so this
module imports - and ``register_builtin_handlers()`` / ``get_handler("pdf")``
succeed - WITHOUT the optional stack installed. Only ``PdfHandler.end()``
touches WeasyPrint, and it translates the two STACK failure modes into a SPLIT
actionable error (one shared ``_stack_error`` helper so ``preflight()`` and
``end()`` can't drift): a missing PYTHON package raises ``ImportError`` →
name ONLY the ``[pdf]`` pip extra (the common case, no Pango); a missing NATIVE
library (Pango / HarfBuzz / fontconfig) surfaces as ``OSError`` from the CFFI
``dlopen`` → name the native libraries + a ``sys.platform``-forked install hint.
The PDF render and the file WRITE are split so a genuine I/O failure (unwritable
path, full disk) surfaces as its own actionable error, never mislabeled as a
missing dependency.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, BinaryIO

from sigwood.common.finding import Finding, RunSummary
from sigwood.common.output import OutputHandler, register_handler
from sigwood.common.paths import private_mkdir, private_write_bytes
from sigwood.outputs.html import render_report_html

# ImportError arm - the [pdf] python package is absent (the common case). Names
# ONLY the pip extra, never Pango. Voice: lowercase-led, raised bare
# (cli.main owns the `sigwood:` prefix), the actionable `- run:` tail with the
# extra quoted for shell safety.
_PDF_PIP_ERROR = "pdf output needs the [pdf] extra - run: pip install 'sigwood[pdf]'"

# OSError arm - package present, native libraries won't load. {hint} is platform-
# forked below; the native libs are named here so the fix is unambiguous.
_PDF_NATIVE_ERROR_BASE = (
    "pdf output: the [pdf] package is installed but can't load the native text "
    "libraries (Pango/HarfBuzz/fontconfig) - {hint}"
)
_PDF_NATIVE_HINTS = {
    "darwin": "run: brew install pango",
    "linux": "install your distro's Pango libraries "
    "(e.g. apt install libpango-1.0-0, or dnf install pango)",
}
# Unrecognised platform (win32, …): no manager guessed - point at the README.
_PDF_NATIVE_HINT_OTHER = "see the README's pdf section for the native text libraries"


def _native_hint() -> str:
    """The platform-specific install hint for the OSError (native-libs) arm."""
    return _PDF_NATIVE_HINTS.get(sys.platform, _PDF_NATIVE_HINT_OTHER)


def _stack_error(exc: ImportError | OSError) -> str:
    """Translate a WeasyPrint-stack failure into ONE actionable message, split by
    failure mode so ``preflight()`` and ``end()`` can't drift:

    - ``ImportError`` → the ``[pdf]`` python package is absent (the common case);
      name ONLY the pip extra, never Pango.
    - ``OSError`` → the package is present but the native Pango / HarfBuzz /
      fontconfig libraries won't load; name them + a ``sys.platform``-forked hint.

    Raised bare as a ``ValueError`` by the caller - ``cli.main`` owns the
    ``sigwood:`` prefix. The genuine file-write ``OSError`` in ``end()`` is a
    SEPARATE arm and never reaches here (it must not be mislabeled as a missing
    dependency)."""
    if isinstance(exc, ImportError):
        return _PDF_PIP_ERROR
    return _PDF_NATIVE_ERROR_BASE.format(hint=_native_hint())

# Refused destination: pdf is binary, so a bare ``-f pdf`` to an interactive
# terminal would spew bytes. The CLI raises this BEFORE the stack preflight
# (terminal-safety wins; a missing stack must never mask it), and
# ``_build_output_handler`` raises it defensively for programmatic callers.
PDF_TTY_ERROR = (
    "pdf output can't go to a terminal; pass --out=PATH or set report_dir"
)


def _import_weasyprint() -> Any:
    """Import seam #1 - returns the ``weasyprint`` module; raises ``ImportError``
    when the Python package is absent. Lazy (never imported at module load) so
    registration never depends on the optional stack. Monkeypatch this to inject
    ``ImportError`` in tests."""
    import weasyprint  # noqa: PLC0415 - deliberately lazy

    return weasyprint


def _render_pdf_bytes(html_str: str) -> bytes:
    """Import seam #2 - render to PDF bytes (the file write is the caller's job).

    The native Pango/cairo load happens inside ``write_pdf`` and surfaces as
    ``OSError`` when the native libraries are missing - so this whole call sits
    inside the stack-error translation. Returning bytes (``write_pdf()`` with no
    path) keeps a genuine file-write failure OUT of that translation. Monkeypatch
    this to inject ``OSError`` (or a byte-returning recorder) in tests."""
    weasyprint = _import_weasyprint()
    return weasyprint.HTML(string=html_str).write_pdf()


class PdfHandler(OutputHandler):
    """Write findings as a PDF report file (HTML rendered through WeasyPrint)."""

    def __init__(
        self,
        stream: BinaryIO | None = None,
        output_path: Path | None = None,
        verbose_level: int = 0,
        *,
        max_findings_per_detector: int = 100,
    ) -> None:
        # Exactly one of ``stream`` / ``output_path`` is set by the runner:
        # ``stream`` (sys.stdout.buffer) for a pipe, ``output_path`` for a file.
        # No CWD default - the surprise-file class is deleted. Neither set is a
        # caller misuse - fail fast with an actionable error, not a raw
        # AttributeError deep in end()'s file write. pdf must never silently
        # default to a stream (binary-safety - the TTY guard lives at the CLI seam).
        if stream is None and output_path is None:
            raise ValueError("PdfHandler requires a stream or an output_path")
        self._stream = stream
        self._output_path = output_path
        self._verbose_level = verbose_level
        self._max_findings_per_detector = max_findings_per_detector
        self._findings: list[Finding] = []
        self._run_summary: RunSummary | None = None

    @classmethod
    def preflight(cls) -> None:
        """Fail-fast probe of the WeasyPrint/Pango stack BEFORE load/detect.

        A throwaway 1-element render exercises BOTH failure modes: a missing
        Python package (``ImportError`` from the lazy import) AND missing native
        libraries (``OSError`` from the CFFI ``dlopen`` inside ``write_pdf``).
        Both translate to the one actionable stack error - same translation as
        ``end()``."""
        try:
            _render_pdf_bytes("<html><body>preflight</body></html>")
        except (ImportError, OSError) as exc:
            raise ValueError(_stack_error(exc)) from exc

    def begin(self, run_summary: RunSummary) -> None:
        """Store run summary for the report header."""
        self._run_summary = run_summary

    def write(self, findings: list[Finding]) -> None:
        """Accumulate findings for rendering at end()."""
        self._findings.extend(findings)

    def end(self) -> None:
        """Render the HTML twin to PDF bytes via WeasyPrint, then write the file.

        The stack-error translation wraps ONLY the render; the mkdir + write are
        translated separately so an I/O failure surfaces as itself (not the
        dependency error) and never reaches the user as a raw traceback."""
        html_str = render_report_html(
            self._findings,
            self._run_summary,
            verbose_level=self._verbose_level,
            max_findings_per_detector=self._max_findings_per_detector,
        )
        try:
            pdf_bytes = _render_pdf_bytes(html_str)
        except (ImportError, OSError) as exc:
            raise ValueError(_stack_error(exc)) from exc
        if self._stream is not None:
            # Pipe target (sys.stdout.buffer) - the caller owns the stream; we
            # never close it. Flush so piped bytes are not lost on a buffered exit.
            self._stream.write(pdf_bytes)
            self._stream.flush()
            return
        try:
            private_mkdir(self._output_path.parent)
            private_write_bytes(self._output_path, pdf_bytes)
        except OSError as exc:
            raise ValueError(f"could not write pdf to {self._output_path}: {exc}") from exc


register_handler("pdf", PdfHandler)
