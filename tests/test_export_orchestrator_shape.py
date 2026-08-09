"""Export orchestrator - new [export.<backend>] config shape coverage.

Covers the fetch seam where ``run_export`` reads
``config[resolved_backend]`` at lines 155 and 165. A
stub-backend test that drives the actual ``run_export`` exposes this - it
KeyErrors today if any site still reads the top-level key.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from sigwood import cli, exporters
from sigwood.common import config as cfg
from sigwood.common.display import fmt_window, set_display_utc
from sigwood.common.errors import UsageError
from sigwood.common.paths import private_write_bytes
from sigwood.exporters import run_export


def _materialized_write(outpath: Path, data: bytes = b"") -> tuple[int, dict[str, Any]]:
    private_write_bytes(outpath, data)
    return 0, {"bytes": len(data), "paths": [outpath]}


# ── backend selection reads config["export"][name], not top-level ────────────


def test_backend_selection_reads_from_export_namespace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A config with [splunk] at the TOP level must NOT auto-select splunk -
    the new clean-break shape requires [export.splunk]."""
    config = {
        "sigwood": {"export_dir": str(tmp_path)},
        # WRONG shape - top-level [splunk]. Must NOT activate.
        "splunk": {"host": "192.0.2.20", "port": 8089,
                   "query": {"default": {"spl": "x"}}},
    }
    with pytest.raises(ValueError, match=r"no export backend configured"):
        run_export(
            config=config, backend=None, query_names=[],
            since=datetime(2026, 6, 1), until=datetime(2026, 6, 2),
            out=None, verbose=False,
        )


def test_backend_selection_from_export_namespace_succeeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    config = {
        "sigwood": {"export_dir": str(tmp_path)},
        "export": {"splunk": {"host": "192.0.2.20", "port": 8089,
                              "query": {"default": {"spl": "x"}}}},
    }
    # Stub fetch / write so no real Splunk call happens.
    from sigwood.exporters import splunk as splunk_module
    monkeypatch.setattr(
        splunk_module, "fetch",
        lambda *a, **kw: ([], {"units": 0, "unit_label": "chunks"}),
    )
    monkeypatch.setattr(
        splunk_module, "write",
        lambda rows, outpath, verbose: _materialized_write(outpath),
    )
    # Should auto-select splunk and not raise.
    run_export(
        config=config, backend=None, query_names=[],
        since=datetime(2026, 6, 1), until=datetime(2026, 6, 2),
        out=None, verbose=False,
    )


# ── run_export fetch-seam - stub backend, verify what gets passed in ────────


class _StubBackend:
    """Module-shaped stub: exposes the four duck-typed callables run_export
    needs. captured = the kwargs each was called with."""

    captured: dict[str, Any] = {}

    @staticmethod
    def is_configured(backend_cfg: dict) -> bool:
        return bool(backend_cfg.get("host", "").strip())

    @staticmethod
    def summary_descriptor(backend_cfg: dict) -> str:
        return backend_cfg.get("host", "")

    @staticmethod
    def fetch(query_config, backend_config, since, until, verbose, *, skip_confirm=False):
        # Capture the backend_config the orchestrator hands us - this is the
        # seam under test. Reading the wrong seam would take config["splunk"]
        # (top-level), which this config has no such key for → KeyError or
        # empty dict.
        _StubBackend.captured["backend_config"] = backend_config
        _StubBackend.captured["query_config"] = query_config
        return ([], {"units": 0, "unit_label": "chunks"})

    @staticmethod
    def write(rows, outpath, verbose):
        _StubBackend.captured["outpath"] = outpath
        return _materialized_write(outpath)


def test_run_export_fetch_receives_export_namespace_backend_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Drive the actual run_export call. The fetch seam MUST receive the
    [export.<stub>] stanza dict, not the empty top-level config['<stub>']."""
    _StubBackend.captured = {}
    # Register the stub under the existing splunk slot via monkeypatch on the
    # loaded-module cache: the orchestrator does importlib on a name in
    # _KNOWN_BACKENDS, then is_configured / fetch / write on that module.
    monkeypatch.setattr(exporters, "_load_backend", lambda name: _StubBackend)
    monkeypatch.setattr(exporters, "_KNOWN_BACKENDS", ("splunk",))

    config = {
        "sigwood": {"export_dir": str(tmp_path)},
        "export": {"splunk": {
            "host": "192.0.2.20",
            "port": 8089,
            "query": {"default": {"spl": "search *", "output_basename": "syslog"}},
        }},
        # Decoy: top-level key with junk. A top-level reader would read THIS.
        "splunk": {"host": "BOGUS-do-not-use", "query": {}},
    }
    run_export(
        config=config, backend="splunk", query_names=[],
        since=datetime(2026, 6, 1), until=datetime(2026, 6, 2),
        out=None, verbose=False,
    )

    backend_cfg = _StubBackend.captured["backend_config"]
    assert backend_cfg.get("host") == "192.0.2.20"
    assert backend_cfg.get("host") != "BOGUS-do-not-use"


# ── Splunk no-query under [export.splunk] → actionable ValueError ────────────


def test_splunk_no_query_under_export_namespace_raises_actionable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """No shipped default query. [export.splunk] with host set but no query
    stanza must raise a ValueError naming [export.splunk.query.<name>]."""
    config = {
        "sigwood": {"export_dir": str(tmp_path)},
        "export": {"splunk": {"host": "192.0.2.20", "port": 8089}},
        # NO query.* - bare sigwood export must surface an actionable error.
    }
    with pytest.raises(ValueError) as exc_info:
        run_export(
            config=config, backend=None, query_names=[],
            since=datetime(2026, 6, 1), until=datetime(2026, 6, 2),
            out=None, verbose=False,
        )
    msg = str(exc_info.value)
    assert "[export.splunk.query." in msg


@pytest.mark.parametrize(
    "argv",
    (["export"], ["export", "splunk"]),
    ids=("auto-backend", "explicit-backend"),
)
def test_cli_bare_export_rejects_default_among_multiple_queries(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path.chmod(0o700)
    config = {
        "sigwood": {"root": str(tmp_path)},
        "export": {"splunk": {
            "host": "192.0.2.20",
            "port": 8089,
            "query": {
                "auth": {"spl": "search index=auth"},
                "default": {"spl": "search index=main"},
            },
        }},
    }
    monkeypatch.setattr(cfg, "load", lambda _path=None: config)

    def _unexpected_fetch(*_args, **_kwargs):
        pytest.fail("ambiguous bare export reached the backend fetch seam")

    from sigwood.exporters import splunk as splunk_module
    monkeypatch.setattr(splunk_module, "fetch", _unexpected_fetch)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(argv)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "sigwood: multiple queries for backend 'splunk': auth, default - "
        "specify one: sigwood export splunk <query>\n"
    )


# ── the no-timeframe default window anchors on display-timezone midnights ────


def test_default_window_anchors_follow_the_knob(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pin_tz, restore_display_utc,
) -> None:
    """since/until None → the default window anchors on DISPLAY-timezone
    midnights: local yesterday/today (manual fixed-offset arithmetic under
    Etc/GMT+6) with the knob off, UTC midnights with it on. Expected values
    are computed before AND after the call so a midnight rollover mid-test
    cannot flake."""
    pin_tz("Etc/GMT+6")

    windows: list[tuple] = []

    class _WindowStub:
        @staticmethod
        def is_configured(backend_cfg):
            return True

        @staticmethod
        def summary_descriptor(backend_cfg):
            return "stub"

        @staticmethod
        def fetch(query_config, backend_config, since, until, verbose, *,
                  skip_confirm=False):
            windows.append((since, until))
            return ([], {"units": 0, "unit_label": "chunks"})

        @staticmethod
        def write(rows, outpath, verbose):
            return _materialized_write(outpath)

    monkeypatch.setattr(exporters, "_load_backend", lambda name: _WindowStub)
    monkeypatch.setattr(exporters, "_KNOWN_BACKENDS", ("splunk",))
    config = {
        "sigwood": {"export_dir": str(tmp_path)},
        "export": {"splunk": {"host": "192.0.2.20",
                              "query": {"default": {"spl": "search *"}}}},
    }

    def expected(use_utc: bool) -> tuple:
        # Manual arithmetic, independent of the code under test: the anchor
        # is now in the display zone (a FIXED -6h offset when local).
        if use_utc:
            anchor = datetime.now(timezone.utc)
        else:
            anchor = datetime.now(timezone.utc).astimezone(
                timezone(timedelta(hours=-6))
            )
        today = anchor.replace(hour=0, minute=0, second=0, microsecond=0)
        return (today - timedelta(days=1), today)

    before = expected(False)
    run_export(config=config, backend="splunk", query_names=[],
               since=None, until=None, out=None, verbose=False)
    after = expected(False)
    assert windows[-1] in (before, after)

    before = expected(True)
    run_export(config=config, backend="splunk", query_names=[],
               since=None, until=None, out=None, verbose=False, use_utc=True)
    after = expected(True)
    assert windows[-1] in (before, after)


@pytest.mark.parametrize(
    ("since", "until", "expected"),
    (
        (
            None,
            None,
            (
                datetime(2026, 8, 5, tzinfo=timezone.utc),
                datetime(2026, 8, 6, tzinfo=timezone.utc),
            ),
        ),
        (
            datetime(2026, 8, 5, 13, 56, tzinfo=timezone.utc),
            None,
            (
                datetime(2026, 8, 5, 13, 56, tzinfo=timezone.utc),
                datetime(2026, 8, 6, 13, 56, tzinfo=timezone.utc),
            ),
        ),
        (
            None,
            datetime(2026, 8, 4, 14, 45, tzinfo=timezone.utc),
            (
                datetime(2026, 8, 3, 14, 45, tzinfo=timezone.utc),
                datetime(2026, 8, 4, 14, 45, tzinfo=timezone.utc),
            ),
        ),
        (
            datetime(2026, 8, 4, 9, 30, tzinfo=timezone.utc),
            datetime(2026, 8, 4, 14, 45, tzinfo=timezone.utc),
            (
                datetime(2026, 8, 4, 9, 30, tzinfo=timezone.utc),
                datetime(2026, 8, 4, 14, 45, tzinfo=timezone.utc),
            ),
        ),
        (
            None,
            datetime(2026, 8, 3, 23, 59, 59, tzinfo=timezone.utc),
            (
                datetime(2026, 8, 3, tzinfo=timezone.utc),
                datetime(2026, 8, 4, tzinfo=timezone.utc),
            ),
        ),
    ),
    ids=("neither", "since-only", "until-only", "both", "until-only-eod"),
)
def test_run_export_resolves_endpoint_defaults_as_one_pair(
    since: datetime | None,
    until: datetime | None,
    expected: tuple[datetime, datetime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    restore_display_utc,
) -> None:
    """The fetch seam and permanent narration share one pair-aware window."""
    fixed_now = datetime(2026, 8, 6, 13, 56, tzinfo=timezone.utc)
    observed: list[tuple[datetime, datetime]] = []

    class _FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz is None else fixed_now.astimezone(tz)

    class _PairStub:
        @staticmethod
        def is_configured(_backend_cfg):
            return True

        @staticmethod
        def summary_descriptor(_backend_cfg):
            return "stub"

        @staticmethod
        def fetch(
            _query_config,
            _backend_config,
            resolved_since,
            resolved_until,
            _verbose,
            *,
            skip_confirm=False,
        ):
            observed.append((resolved_since, resolved_until))
            return [], {"units": 0, "unit_label": "chunks"}

        @staticmethod
        def write(_rows, outpath, _verbose):
            return _materialized_write(outpath)

    monkeypatch.setattr(exporters, "datetime", _FixedDateTime)
    monkeypatch.setattr(exporters, "_load_backend", lambda _name: _PairStub)
    monkeypatch.setattr(exporters, "_KNOWN_BACKENDS", ("splunk",))
    config = {
        "sigwood": {"export_dir": str(tmp_path)},
        "export": {
            "splunk": {
                "host": "192.0.2.20",
                "query": {"default": {"spl": "search *"}},
            }
        },
    }

    run_export(
        config=config,
        backend="splunk",
        query_names=[],
        since=since,
        until=until,
        out=None,
        verbose=False,
        use_utc=True,
    )

    assert observed == [expected]
    rendered = capsys.readouterr().out
    assert f"window: {fmt_window(expected)}" in rendered


@pytest.mark.parametrize(
    ("since", "until", "display_now", "resolved"),
    (
        (
            datetime(2026, 8, 6, 14, 30, tzinfo=timezone.utc),
            None,
            datetime(2026, 8, 6, 13, 56, tzinfo=timezone.utc),
            (
                datetime(2026, 8, 6, 14, 30, tzinfo=timezone.utc),
                datetime(2026, 8, 6, 13, 56, tzinfo=timezone.utc),
            ),
        ),
        (
            datetime(2026, 8, 6, 15, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 6, 14, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 6, 13, 56, tzinfo=timezone.utc),
            (
                datetime(2026, 8, 6, 15, 0, tzinfo=timezone.utc),
                datetime(2026, 8, 6, 14, 0, tzinfo=timezone.utc),
            ),
        ),
        (
            datetime(2026, 8, 6, 14, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 6, 14, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 6, 13, 56, tzinfo=timezone.utc),
            (
                datetime(2026, 8, 6, 14, 0, tzinfo=timezone.utc),
                datetime(2026, 8, 6, 14, 0, tzinfo=timezone.utc),
            ),
        ),
    ),
    ids=("future-since-only", "inverted", "equal"),
)
def test_resolve_export_window_rejects_non_positive_pair(
    since: datetime | None,
    until: datetime | None,
    display_now: datetime,
    resolved: tuple[datetime, datetime],
    restore_display_utc,
) -> None:
    """Every resolved export interval is positive before orchestration starts."""
    set_display_utc(True)

    with pytest.raises(UsageError) as exc_info:
        exporters._resolve_export_window(since, until, display_now=display_now)

    assert str(exc_info.value) == (
        f"export window is empty: {fmt_window(resolved)}. "
        "The window start must be earlier than its end."
    )


def test_cli_equal_hours_uses_flag_neutral_empty_window_remedy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    restore_display_utc,
) -> None:
    """The --hours path names the interval rule, not unrelated endpoint flags."""
    tmp_path.chmod(0o700)
    config = {
        "sigwood": {"root": str(tmp_path), "use_utc": True},
        "export": {
            "splunk": {
                "host": "192.0.2.20",
                "query": {"default": {"spl": "search *"}},
            }
        },
    }
    monkeypatch.setattr(cfg, "load", lambda _path=None: config)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["export", "splunk", "--hours=1-1"])

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("sigwood: export window is empty: ")
    assert (
        ". The window start must be earlier than its end.\n"
        "run 'sigwood --help' for usage\n"
    ) in captured.err
    assert "--since" not in captured.err
    assert "--until" not in captured.err


def test_run_export_rejects_inverted_window_before_fetch_or_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    restore_display_utc,
) -> None:
    """A bad pair cannot reach backend work or create a plausible empty artifact."""
    observed_fetches: list[tuple[datetime, datetime]] = []

    class _RejectingWindowStub:
        @staticmethod
        def is_configured(_backend_cfg):
            return True

        @staticmethod
        def summary_descriptor(_backend_cfg):
            return "stub"

        @staticmethod
        def fetch(
            _query_config,
            _backend_config,
            resolved_since,
            resolved_until,
            _verbose,
            *,
            skip_confirm=False,
        ):
            observed_fetches.append((resolved_since, resolved_until))
            return [], {"units": 0, "unit_label": "chunks"}

        @staticmethod
        def write(_rows, outpath, _verbose):
            return _materialized_write(outpath, b"fetched")

    monkeypatch.setattr(exporters, "_load_backend", lambda _name: _RejectingWindowStub)
    monkeypatch.setattr(exporters, "_KNOWN_BACKENDS", ("splunk",))
    config = {
        "export": {
            "splunk": {
                "host": "192.0.2.20",
                "query": {"default": {"spl": "search *"}},
            }
        },
    }

    with pytest.raises(UsageError):
        run_export(
            config=config,
            backend="splunk",
            query_names=[],
            since=datetime(2026, 8, 6, 15, 0, tzinfo=timezone.utc),
            until=datetime(2026, 8, 6, 14, 0, tzinfo=timezone.utc),
            out=str(tmp_path / "export.log"),
            verbose=False,
            use_utc=True,
        )

    assert observed_fetches == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("duration", "expected"),
    (
        (timedelta(minutes=30), "30m"),
        (timedelta(minutes=90), "2h"),
        (timedelta(hours=36), "1.5d"),
        (timedelta(days=1), "1 day"),
        (timedelta(days=2), "2 days"),
    ),
    ids=("thirty-minutes", "ninety-minutes", "thirty-six-hours", "one-day", "two-days"),
)
def test_run_export_narrates_compact_positive_span(
    duration: timedelta,
    expected: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    restore_display_utc,
) -> None:
    """Non-day spans share compact rendering while whole days keep prose."""
    class _SpanStub:
        @staticmethod
        def is_configured(_backend_cfg):
            return True

        @staticmethod
        def summary_descriptor(_backend_cfg):
            return "stub"

        @staticmethod
        def fetch(*_args, **_kwargs):
            return [], {"units": 0, "unit_label": "chunks"}

        @staticmethod
        def write(_rows, outpath, _verbose):
            return _materialized_write(outpath)

    monkeypatch.setattr(exporters, "_load_backend", lambda _name: _SpanStub)
    monkeypatch.setattr(exporters, "_KNOWN_BACKENDS", ("splunk",))
    config = {
        "export": {
            "splunk": {
                "host": "192.0.2.20",
                "query": {"default": {"spl": "search *"}},
            }
        },
    }
    since = datetime(2026, 8, 4, 9, 0, tzinfo=timezone.utc)

    run_export(
        config=config,
        backend="splunk",
        query_names=[],
        since=since,
        until=since + duration,
        out=str(tmp_path / "export.log"),
        verbose=False,
        use_utc=True,
    )

    window_line = next(
        line for line in capsys.readouterr().out.splitlines() if line.startswith("window:")
    )
    assert window_line.endswith(f"  ·  {expected}")
