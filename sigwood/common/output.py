"""Reporter, OutputHandler base class, and handler registry.

Findings flow: list[Finding] → Reporter → one or more OutputHandler instances.

Detectors never know how output is handled. Adding a new output format means
implementing an OutputHandler subclass whose module registers it on import, then
adding that module to register_builtin_handlers() below.
"""

from __future__ import annotations

import importlib
from abc import ABC, abstractmethod

from sigwood.common.finding import Finding, RunSummary


class OutputHandler(ABC):
    """Base class for all output format handlers.

    Implement begin(), write(), and end() in each subclass.
    The framework calls them in order: begin → write (once per detector group) → end.
    """

    @abstractmethod
    def begin(self, run_summary: RunSummary) -> None:
        """Called once before any findings are written. Render the run summary here."""
        raise NotImplementedError

    @abstractmethod
    def write(self, findings: list[Finding]) -> None:
        """Called with findings from one or more detectors."""
        raise NotImplementedError

    @abstractmethod
    def end(self) -> None:
        """Called once after all findings have been written. Flush/close resources here."""
        raise NotImplementedError

    @classmethod
    def preflight(cls) -> None:
        """Optional pre-run readiness probe (e.g. an optional native stack).

        Called by the CLI BEFORE any log is read so a missing dependency barfs
        immediately, not after expensive load/detect work. Default: no-op.
        ``PdfHandler`` overrides it to probe the WeasyPrint/Pango stack."""
        return None


class Reporter:
    """Orchestrates output across one or more registered OutputHandler instances."""

    def __init__(self, handlers: list[OutputHandler]) -> None:
        self._handlers = handlers

    def begin(self, run_summary: RunSummary) -> None:
        """Call begin() on all handlers. Invoke before the detection loop."""
        for handler in self._handlers:
            handler.begin(run_summary)

    def write(self, findings: list[Finding]) -> None:
        """Call write() on all handlers. Invoke after detection completes."""
        for handler in self._handlers:
            handler.write(findings)

    def end(self) -> None:
        """Call end() on all handlers. Flush and close any open resources."""
        for handler in self._handlers:
            handler.end()

    def run(self, findings: list[Finding], run_summary: RunSummary) -> None:
        """Convenience method: begin → write → end in a single call."""
        self.begin(run_summary)
        self.write(findings)
        self.end()


_HANDLER_REGISTRY: dict[str, type[OutputHandler]] = {}


def register_handler(name: str, cls: type[OutputHandler]) -> None:
    """Register an OutputHandler subclass under a format name (e.g. 'text', 'json')."""
    _HANDLER_REGISTRY[name] = cls


def register_builtin_handlers() -> None:
    """Import built-in output modules so their handlers register themselves.

    ``pdf`` imports cleanly WITHOUT the optional WeasyPrint stack (the import is
    lazy inside ``PdfHandler.end()``), so registration never depends on it - an
    uninstalled stack yields the actionable error at write time, not "unknown
    format pdf"."""
    for module in ("text", "json", "csv", "html", "pdf"):
        importlib.import_module(f"sigwood.outputs.{module}")


def get_handler(name: str) -> type[OutputHandler]:
    """Return the OutputHandler class for the given format name.

    Raises ValueError with an actionable message if the format is not registered.
    """
    register_builtin_handlers()
    if name not in _HANDLER_REGISTRY:
        available = ", ".join(sorted(_HANDLER_REGISTRY))
        raise ValueError(
            f"unknown output format '{name}' - available: {available}"
        )
    return _HANDLER_REGISTRY[name]
