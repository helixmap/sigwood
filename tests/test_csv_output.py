"""CSV handler - the remediation worklist."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

import numpy as np

from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.outputs.csv import _FIELDNAMES, CsvHandler

_W = (
    datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
    datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
)


def _summary() -> RunSummary:
    return RunSummary(
        data_window=_W, record_counts={}, data_size_bytes=0,
        detectors_run=[], detectors_skipped={},
    )


def _finding(**kw) -> Finding:
    base = dict(
        detector="beacon",
        severity=Severity.HIGH,
        title="192.0.2.10 → 192.0.2.20:443/tcp",
        description="A regular beat.",
        evidence={"beacon_score": np.float64(0.61)},
        next_steps=["Inspect the flow", "Pivot on the dst"],
        ts_generated=datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc),
        data_window=_W,
    )
    base.update(kw)
    return Finding(**base)


def _emit(findings, *, verbose_level: int = 0) -> str:
    buf = io.StringIO()
    h = CsvHandler(stream=buf, verbose_level=verbose_level)
    h.begin(_summary())
    h.write(findings)
    h.end()
    return buf.getvalue()


def _rows(text: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(text)))


_DATA_CONTROLS = ("\x1b", "\x00", "\x07", "\r", "\x9b")


def _assert_no_data_controls(value: str) -> None:
    for ch in _DATA_CONTROLS:
        assert ch not in value


def test_fixed_column_set_and_order() -> None:
    header = _emit([_finding()]).splitlines()[0]
    assert header.split(",") == _FIELDNAMES
    assert _FIELDNAMES == [
        "severity", "detector", "finding", "next_steps", "description",
        "signals", "data_window_start", "data_window_end", "status", "notes",
    ]


def test_one_row_per_finding() -> None:
    rows = _rows(_emit([_finding(), _finding(), _finding()]))
    assert len(rows) == 3


def test_finding_column_is_the_title() -> None:
    row = _rows(_emit([_finding()]))[0]
    assert row["finding"] == "192.0.2.10 → 192.0.2.20:443/tcp"


def test_next_steps_newlines_survive_csv_round_trip() -> None:
    row = _rows(_emit([_finding()]))[0]
    assert row["next_steps"] == "Inspect the flow\nPivot on the dst"


def test_formula_like_string_cells_are_prefixed(monkeypatch) -> None:
    monkeypatch.setattr(
        CsvHandler,
        "_signals",
        staticmethod(lambda _finding: "@signal"),
    )
    row = _rows(_emit([
        _finding(
            detector="\tdetector",
            title="=cmd",
            description="+description",
            next_steps=["-investigate"],
        )
    ]))[0]

    assert row["finding"] == "'=cmd"
    assert row["description"] == "'+description"
    assert row["next_steps"] == "'-investigate"
    assert row["signals"] == "'@signal"
    assert row["detector"] == "detector"


def test_control_bytes_stripped_from_string_cells(monkeypatch) -> None:
    hostile = "Z9HOST" + "".join(_DATA_CONTROLS) + "ILE9Z"
    monkeypatch.setattr(
        CsvHandler,
        "_signals",
        staticmethod(lambda _finding: hostile),
    )
    row = _rows(_emit([
        _finding(
            detector=hostile,
            title=hostile,
            description=hostile,
            next_steps=[hostile],
        )
    ]))[0]

    for key in ("detector", "finding", "description", "next_steps", "signals"):
        assert "Z9HOSTILE9Z" in row[key]
        _assert_no_data_controls(row[key])


def test_next_steps_strip_controls_but_keep_join_newline() -> None:
    row = _rows(_emit([_finding(next_steps=["a\x00", "b"])]))[0]
    assert row["next_steps"] == "a\nb"


def test_strip_happens_before_formula_guard() -> None:
    row = _rows(_emit([_finding(title="\x1b=cmd")]))[0]
    assert row["finding"] == "'=cmd"


def test_multibyte_glyphs_survive_csv_control_strip() -> None:
    row = _rows(_emit([_finding(title="flow 192.0.2.10 → 198.51.100.20\x1b")]))[0]
    assert row["finding"] == "flow 192.0.2.10 → 198.51.100.20"


def test_normal_string_cells_are_not_prefixed() -> None:
    row = _rows(_emit([_finding()]))[0]
    assert row["finding"] == "192.0.2.10 → 192.0.2.20:443/tcp"
    assert row["description"] == "A regular beat."
    assert row["next_steps"] == "Inspect the flow\nPivot on the dst"


def test_status_and_notes_seeded_empty() -> None:
    row = _rows(_emit([_finding()]))[0]
    assert row["status"] == ""
    assert row["notes"] == ""


def test_signals_dict_and_bool_render_human_no_brackets() -> None:
    # dns zeek singleton curates rcode_distribution (dict) + was_blocked (bool).
    f = _finding(
        detector="dns",
        evidence={
            "source": "zeek",
            "rcode_distribution": {"NOERROR": 10, "NXDOMAIN": 2},
            "was_blocked": True,
            "unique_sources": 3,
        },
    )
    signals = _rows(_emit([f]))[0]["signals"]
    # dict -> compact key:value (sorted), bool -> lowercase, no braces/quotes/True
    assert "rcode_distribution=NOERROR:10,NXDOMAIN:2" in signals
    assert "was_blocked=true" in signals
    assert "{" not in signals and "}" not in signals
    assert "True" not in signals


def test_syslog_family_signals_are_curated_without_raw_samples() -> None:
    f = _finding(
        detector="syslog",
        severity=Severity.MEDIUM,
        title="host-family",
        evidence={
            "tier": "family", "host": "host-family", "program": "sshd",
            "line_count": 2, "program_total": 4412,
            "start_ts": 1.0, "end_ts": 121.0,
            "first_seen": "1970-01-01T00:00:01+00:00",
            "span_seconds": 120.0, "sample_raw": ["raw-a", "raw-b"],
            "member_fragments": ["accepted from 192.0.2.9"],
            "label": None,
        },
    )
    row = _rows(_emit([f]))[0]
    assert row["finding"] == "host-family"
    assert row["signals"] == (
        "program=sshd; line_count=2; program_total=4412; span_seconds=120.0; "
        "first_seen=1970-01-01T00:00:01+00:00"
    )
    assert "sample_raw" not in row["signals"]
    assert "member_fragments" not in row["signals"]
    assert "start_ts" not in row["signals"]
    assert "end_ts" not in row["signals"]


def test_syslog_needle_signals_add_first_seen_only() -> None:
    f = _finding(
        detector="syslog",
        severity=Severity.LOW,
        title="journal needle sentinel",
        evidence={
            "host": "host-journal", "program": "cron", "program_total": 1,
            "template_id": 7, "template_str": "cron: journal needle sentinel",
            "count": 1, "threshold": 9,
            "first_seen": "2026-07-12T21:57:33+00:00",
            "self_stamped": False,
            "member_fragments": ["must-not-reach-csv"],
        },
    )
    row = _rows(_emit([f]))[0]
    assert row["signals"] == (
        "template_str=cron: journal needle sentinel; host=host-journal; "
        "program_total=1; count=1; threshold=9; "
        "first_seen=2026-07-12T21:57:33+00:00"
    )
    assert "self_stamped" not in row["signals"]
    assert "member_fragments" not in row["signals"]


def test_verbosity_invariant() -> None:
    f = [_finding()]
    assert _emit(f, verbose_level=0) == _emit(f, verbose_level=2)


def test_description_always_present() -> None:
    # description is NOT verbose-gated in the worklist.
    row = _rows(_emit([_finding()], verbose_level=0))[0]
    assert row["description"] == "A regular beat."


def test_never_capped() -> None:
    # csv ignores any cap notion - every finding is a worklist row.
    rows = _rows(_emit([_finding() for _ in range(250)]))
    assert len(rows) == 250


def test_timestamps_iso_with_offset() -> None:
    row = _rows(_emit([_finding()]))[0]
    # ISO-8601 with an explicit offset (local; +00:00 under the TZ=UTC pin).
    assert row["data_window_start"] == "2026-06-01T12:00:00+00:00"
    assert "+" in row["data_window_start"]


def test_reconfigures_stream_newline_for_safe_quoting() -> None:
    """csv must run on a newline='' stream or embedded-newline cells mangle on
    newline-translating platforms; a reconfigurable stream (stdout) is set."""
    class _RecordingStream(io.StringIO):
        def __init__(self) -> None:
            super().__init__()
            self.reconfigured: dict | None = None

        def reconfigure(self, **kw):
            self.reconfigured = kw

    s = _RecordingStream()
    h = CsvHandler(stream=s)
    h.begin(_summary())
    h.write([_finding()])
    h.end()
    assert s.reconfigured == {"newline": ""}
    assert "192.0.2.10" in s.getvalue()  # content still wrote


# ── negative guard: csv stays on the worklist path, NOT the reading-surface model ──
def test_csv_does_not_import_render_model() -> None:
    """csv is the worklist consumer (curated_evidence), deliberately independent
    of the text/html reading-surface render model. It must NOT couple to it."""
    import inspect

    import sigwood.outputs.csv as csv_mod

    src = inspect.getsource(csv_mod)
    assert "_render_model" not in src
    assert "project_row" not in src


# ── display timezone switch: the worklist offset follows it ──────────────────
def test_data_window_offset_follows_display_switch(pin_tz, restore_display_utc) -> None:
    """The worklist's ISO-8601 timestamps carry the DISPLAY offset: the pinned
    local offset (-06:00 under Etc/GMT+6) by default, +00:00 under the display
    switch. Expected strings by manual offset arithmetic on the fixed window."""
    from sigwood.common.display import set_display_utc

    pin_tz("Etc/GMT+6")
    row = _rows(_emit([_finding()]))[0]
    assert row["data_window_start"] == "2026-06-01T06:00:00-06:00"
    assert row["data_window_end"] == "2026-06-01T12:30:00-06:00"

    set_display_utc(True)
    row = _rows(_emit([_finding()]))[0]
    assert row["data_window_start"] == "2026-06-01T12:00:00+00:00"
    assert row["data_window_end"] == "2026-06-01T18:30:00+00:00"
