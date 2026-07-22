"""JSON output handler - the lossless machine contract.

The IMPORT / pipe / SIEM surface: correctly typed, ISO-8601 **UTC**, always-full
(verbosity-invariant), never capped. Every evidence value passes through
``to_jsonable`` (the single serialization owner) so numpy / pandas / nan / set
values serialise as valid, correctly-typed JSON; the writer adds
``allow_nan=False`` so a value that ever slips past normalisation makes the
writer RAISE rather than emit bare ``NaN`` (invalid JSON).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, TextIO

from sigwood import __version__ as _SIGWOOD_VERSION
from sigwood.common.finding import Finding, RunSummary
from sigwood.common.output import OutputHandler, register_handler
from sigwood.outputs._serialize import to_jsonable

# Bumps ONLY on a BREAKING change to the json contract (a removed/renamed field
# or a changed type) - additive fields do NOT bump it. Document this
# compatibility rule in the schema docs when they are added.
_SCHEMA_VERSION = 1


def _iso_utc(dt: datetime) -> str:
    """ISO-8601 in UTC. A naive datetime is assumed UTC (mirrors the human
    renderer's naive handling); an aware datetime is converted to UTC - so the
    machine contract never echoes whatever incidental zone arrived."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


class JsonHandler(OutputHandler):
    """Write findings as a single JSON object ({run_summary, findings}) to stdout or a file."""

    def __init__(self, stream: TextIO = sys.stdout, verbose_level: int = 0) -> None:
        # verbose_level is accepted for registry uniformity but UNUSED - json is
        # always-full (verbosity-invariant).
        self._stream = stream
        self._verbose_level = verbose_level
        self._findings: list[Finding] = []
        self._run_summary: RunSummary | None = None

    def begin(self, run_summary: RunSummary) -> None:
        """Store run summary for inclusion in output."""
        self._run_summary = run_summary

    def write(self, findings: list[Finding]) -> None:
        """Accumulate findings for serialization at end()."""
        self._findings.extend(findings)

    def end(self) -> None:
        """Serialize the full payload to JSON and write to stream."""
        payload = {
            "sigwood_version": _SIGWOOD_VERSION,
            "schema_version": _SCHEMA_VERSION,
            "run_summary": self._run_summary_to_dict(self._run_summary),
            "findings": [self._finding_to_dict(f) for f in self._findings],
        }
        # to_jsonable is the single serialization owner (normalises evidence:
        # numpy / pandas / nan / set). allow_nan=False is the belt-and-suspenders
        # writer guard - if an un-normalised nan/inf ever reaches here, raise
        # rather than emit invalid JSON.
        json.dump(to_jsonable(payload), self._stream, indent=2, allow_nan=False)
        print(file=self._stream)

    def _finding_to_dict(self, finding: Finding) -> dict[str, Any]:
        """Convert a Finding to a JSON-serializable dict (evidence normalised by
        the whole-payload ``to_jsonable`` pass in ``end()``)."""
        return {
            "detector": finding.detector,
            "severity": finding.severity.name.lower(),
            "title": finding.title,
            "description": finding.description,
            "next_steps": finding.next_steps,
            "evidence": finding.evidence,
            "ts_generated": _iso_utc(finding.ts_generated),
            "data_window": [
                _iso_utc(finding.data_window[0]),
                _iso_utc(finding.data_window[1]),
            ],
        }

    def _run_summary_to_dict(self, run_summary: RunSummary | None) -> dict[str, Any] | None:
        """Convert RunSummary to a JSON-serializable dict."""
        if run_summary is None:
            return None
        return {
            # When no loaded rows establish bounds, the machine summary uses
            # null rather than inventing a window.
            "data_window": (
                None
                if run_summary.data_window is None
                else [
                    _iso_utc(run_summary.data_window[0]),
                    _iso_utc(run_summary.data_window[1]),
                ]
            ),
            "record_counts": run_summary.record_counts,
            "data_size_bytes": run_summary.data_size_bytes,
            "detectors_run": run_summary.detectors_run,
            "detectors_skipped": run_summary.detectors_skipped,
            # Detectors that started but crashed (prep or run) - {} on a clean
            # run. A failed name remains in detectors_run (run = attempted);
            # scheduled-run consumers alert on a non-empty dict (the process
            # also exits nonzero). Additive field - no schema bump.
            "detectors_failed": run_summary.detectors_failed,
            "notes": run_summary.notes,
            "data_sources": run_summary.data_sources,
            "detector_methods": {
                name: (None if tag is None else {"label": tag.label, "named": tag.named})
                for name, tag in run_summary.detector_methods.items()
            },
            "requested_span": (
                run_summary.requested_span.total_seconds()
                if run_summary.requested_span is not None
                else None
            ),
            "suppression": (
                {
                    "enabled": run_summary.suppression.enabled,
                    "connections": run_summary.suppression.connections,
                    "domains": run_summary.suppression.domains,
                    "connection_total": run_summary.suppression.connection_total,
                    "domain_total": run_summary.suppression.domain_total,
                    "host_rows": run_summary.suppression.host_rows,
                    "host_total": run_summary.suppression.host_total,
                    "hosts_matched": run_summary.suppression.hosts_matched,
                }
                if run_summary.suppression is not None
                else None
            ),
        }


register_handler("json", JsonHandler)
