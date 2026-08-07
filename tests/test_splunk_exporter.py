"""Tests for the Splunk exporter framework.

No live Splunk connection - SDK is mocked where needed.
All IP addresses use RFC 5737 documentation space (192.0.2.x).
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from sigwood.cli import _resolve_timeframe
from sigwood.common import config as cfg
from sigwood.common.paths import effective_root
from sigwood.exporters import (
    _auto_filename,
    _normalize_end_of_day_until,
    _resolve_output_path,
    _resolve_queries,
    run_export,
)
from sigwood.exporters.splunk import _build_hour_windows, _get_credentials, fetch, write


def _install_fake_splunk(
    monkeypatch: pytest.MonkeyPatch,
    rows_by_call: list[list[dict]],
) -> list[dict]:
    """Install a deterministic SDK seam and return captured oneshot kwargs."""
    import sigwood.exporters.splunk as splunk_module

    calls: list[dict] = []

    class FakeJobs:
        @staticmethod
        def oneshot(_spl, **kwargs):
            call_index = len(calls)
            calls.append(kwargs)
            return rows_by_call[call_index] if call_index < len(rows_by_call) else []

    class FakeService:
        jobs = FakeJobs()

    class FakeClient:
        @staticmethod
        def connect(**_kwargs):
            return FakeService()

    class FakeResults:
        @staticmethod
        def JSONResultsReader(job):
            return iter(job)

    monkeypatch.setattr(splunk_module, "splunk_client", FakeClient)
    monkeypatch.setattr(splunk_module, "splunk_results", FakeResults)
    return calls


# ── --days full pipeline: local midnight → 24 chunks ─────────────────────────


def test_days_flag_local_midnight_gives_24_chunks() -> None:
    # Simulate a user in UTC-5 running --days=1-1 at 15:00 local.
    # Without the fix, UTC now → .replace(hour=0) gives UTC midnight, which converts
    # to 19:00 local - the window spans 19:00→19:00 local (still 24 chunks but wrong
    # day), and the first chunk starts at hour 19, not 0.
    tz_minus5 = timezone(timedelta(hours=-5))
    local_now = datetime(2026, 5, 31, 15, 0, 0, tzinfo=tz_minus5)

    since, until = _resolve_timeframe({"days": "1-1"}, now=local_now)
    until = _normalize_end_of_day_until(until)
    windows = _build_hour_windows(since, until)

    assert len(windows) == 24
    # First chunk must start at local midnight (hour 0), not a UTC-shifted hour
    assert windows[0][0].hour == 0
    assert windows[0][0] == since
    assert windows[-1][1] == until
    assert _auto_filename("syslog", since, until) == "syslog_20260530_1d.log"


def test_days_export_keeps_midnight_calls_population_narration_and_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    restore_display_utc,
) -> None:
    since, until = _resolve_timeframe(
        {"days": "1-1"},
        now=datetime(2026, 5, 31, 15, tzinfo=timezone.utc),
        use_utc=True,
    )
    assert since is not None and until is not None
    kept = {
        "_time": "2026-05-30T12:00:00+00:00",
        "_raw": "May 30 12:00:00 host.example.test sshd: retained day row",
    }
    calls = _install_fake_splunk(monkeypatch, [*([[]] * 12), [kept]])
    config = {
        "export": {
            "splunk": {
                "host": "192.0.2.20",
                "port": 8089,
                "username": "user",
                "password": "pass",
                "query": {
                    "auth": {
                        "spl": "search index=main",
                        "output_basename": "syslog",
                    }
                },
            }
        }
    }

    run_export(
        config=config,
        backend="splunk",
        query_names=["auth"],
        since=since,
        until=until,
        out=str(tmp_path),
        verbose=False,
        use_utc=True,
    )

    assert len(calls) == 24
    assert (calls[0]["earliest_time"], calls[0]["latest_time"]) == (
        str(int(datetime(2026, 5, 30, tzinfo=timezone.utc).timestamp())),
        str(int(datetime(2026, 5, 30, 1, tzinfo=timezone.utc).timestamp())),
    )
    assert (calls[-1]["earliest_time"], calls[-1]["latest_time"]) == (
        str(int(datetime(2026, 5, 30, 23, tzinfo=timezone.utc).timestamp())),
        str(int(datetime(2026, 5, 31, tzinfo=timezone.utc).timestamp())),
    )
    outpath = tmp_path / "syslog_20260530_1d.log"
    assert outpath.read_text(encoding="utf-8").splitlines() == [kept["_raw"]]
    rendered = capsys.readouterr().out
    assert "window: 2026-05-30 00:00 → 2026-05-31 00:00 UTC  ·  1 day" in rendered
    assert "auth · 1 lines · " in rendered
    assert str(outpath) in rendered


# ── _normalize_end_of_day_until ───────────────────────────────────────────────


def test_normalize_end_of_day_eod() -> None:
    # 23:59:59 → next midnight
    until = datetime(2026, 5, 30, 23, 59, 59)
    result = _normalize_end_of_day_until(until)
    assert result == datetime(2026, 5, 31, 0, 0, 0)


def test_normalize_end_of_day_midnight() -> None:
    # Already on a boundary - unchanged
    until = datetime(2026, 5, 31, 0, 0, 0)
    result = _normalize_end_of_day_until(until)
    assert result == until


def test_normalize_end_of_day_midday_59() -> None:
    # 14:59:59 - hour != 23, must NOT trigger (critical: --hours edge case)
    until = datetime(2026, 5, 30, 14, 59, 59)
    result = _normalize_end_of_day_until(until)
    assert result == until


def test_end_of_day_until_gives_24_chunks() -> None:
    since = datetime(2026, 5, 29, 0, 0, 0)
    # Simulate what --days produces: 23:59:59
    until_raw = datetime(2026, 5, 29, 23, 59, 59)
    # Coarse coverage now ceils the raw endpoint too; normalization remains the
    # compatibility seam that makes narration and auto-naming say next midnight.
    assert len(_build_hour_windows(since, until_raw)) == 24
    until_fixed = _normalize_end_of_day_until(until_raw)
    assert until_fixed == datetime(2026, 5, 30, 0, 0, 0)
    assert len(_build_hour_windows(since, until_fixed)) == 24


# ── _build_hour_windows ───────────────────────────────────────────────────────


def test_build_hour_windows_single_day():
    since = datetime(2026, 5, 29, 0, 0, 0)
    until = datetime(2026, 5, 30, 0, 0, 0)  # 24 hours later, on midnight boundary
    windows = _build_hour_windows(since, until)
    assert len(windows) == 24
    assert windows[0] == (datetime(2026, 5, 29, 0, 0, 0), datetime(2026, 5, 29, 1, 0, 0))
    assert windows[-1] == (datetime(2026, 5, 29, 23, 0, 0), datetime(2026, 5, 30, 0, 0, 0))


def test_build_hour_windows_multi_day():
    since = datetime(2026, 5, 23, 0, 0, 0)
    until = datetime(2026, 5, 30, 0, 0, 0)  # 7 days later
    windows = _build_hour_windows(since, until)
    assert len(windows) == 168  # 7 * 24


def test_build_hour_windows_partial():
    # Coarse calls cover the full request: floor the start and ceil the end.
    since = datetime(2026, 5, 30, 9, 30, 0)
    until = datetime(2026, 5, 30, 14, 45, 0)
    windows = _build_hour_windows(since, until)
    assert len(windows) == 6
    # All chunks are exactly one hour
    for start, end in windows:
        assert (end - start).total_seconds() == 3600
    # All boundaries are on whole-hour marks (no partial-hour chunks)
    for start, end in windows:
        assert start.minute == 0 and start.second == 0 and start.microsecond == 0
        assert end.minute == 0 and end.second == 0 and end.microsecond == 0
    # First chunk starts at the floored hour
    assert windows[0][0].hour == 9
    assert windows[0][0].minute == 0
    # Last chunk ends at the ceiling, 15:00, so no newest data is missed.
    assert windows[-1][1].hour == 15
    assert windows[-1][1].minute == 0


def test_build_hour_windows_nonpositive_request_is_empty() -> None:
    since = datetime(2026, 5, 30, 10, 45, 0)
    until = datetime(2026, 5, 30, 10, 15, 0)

    assert _build_hour_windows(since, until) == []


@pytest.mark.parametrize(
    ("parsed", "fixed_now", "coarse_start", "chunk_count"),
    (
        (
            {"hours": "0-2"},
            datetime(2026, 8, 6, 13, 56, tzinfo=timezone.utc),
            datetime(2026, 8, 6, 11, tzinfo=timezone.utc),
            3,
        ),
        (
            {
                "since": "2026-08-06T09:30:00+00:00",
                "until": "2026-08-06T14:45:00+00:00",
            },
            datetime(2026, 8, 6, 18, tzinfo=timezone.utc),
            datetime(2026, 8, 6, 9, tzinfo=timezone.utc),
            6,
        ),
    ),
    ids=("hours", "explicit"),
)
def test_fetch_coarse_calls_cover_and_rows_trim_to_exact_cli_window(
    parsed: dict[str, str],
    fixed_now: datetime,
    coarse_start: datetime,
    chunk_count: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    since, until = _resolve_timeframe(parsed, now=fixed_now, use_utc=True)
    assert since is not None and until is not None
    at_since = {
        "_time": str(since.timestamp()),
        "_raw": "Aug 06 11:56:00 host.example.test sshd: at lower bound",
    }
    inside_aware = {
        "_time": (since + timedelta(minutes=20)).astimezone(
            timezone(timedelta(hours=2))
        ).isoformat(),
        "_raw": "Aug 06 12:16:00 host.example.test sshd: aware inside",
    }
    inside_naive = {
        "_time": (since + timedelta(minutes=40)).replace(tzinfo=None).isoformat(),
        "_raw": "Aug 06 12:36:00 host.example.test sshd: naive inside",
    }
    source_rows = [
        {
            "_time": (since - timedelta(minutes=1)).isoformat(),
            "_raw": "Aug 06 11:55:00 host.example.test sshd: before",
        },
        at_since,
        inside_aware,
        inside_naive,
        {
            "_time": until.isoformat().replace("+00:00", "Z"),
            "_raw": "Aug 06 13:56:00 host.example.test sshd: at upper bound",
        },
        {
            "_time": (until + timedelta(minutes=1)).isoformat(),
            "_raw": "Aug 06 13:57:00 host.example.test sshd: after",
        },
    ]
    calls = _install_fake_splunk(monkeypatch, [source_rows])

    rows, meta = fetch(
        {"spl": "search index=main"},
        {
            "host": "192.0.2.20",
            "port": 8089,
            "username": "user",
            "password": "pass",
        },
        since,
        until,
        False,
    )

    expected_calls = [
        {
            "count": 0,
            "output_mode": "json",
            "earliest_time": str(int((coarse_start + timedelta(hours=i)).timestamp())),
            "latest_time": str(int((coarse_start + timedelta(hours=i + 1)).timestamp())),
        }
        for i in range(chunk_count)
    ]
    assert calls == expected_calls
    assert rows == [at_since, inside_aware, inside_naive]
    assert meta == {"units": chunk_count, "unit_label": "chunks"}


def test_fetch_mixed_timestamps_trims_and_discloses_timeless_drops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    since = datetime(2026, 8, 6, 9, 30, tzinfo=timezone.utc)
    until = datetime(2026, 8, 6, 10, 30, tzinfo=timezone.utc)
    inside = {
        "_time": "2026-08-06T10:00:00+00:00",
        "_raw": "Aug 06 10:00:00 host.example.test sshd: inside",
    }
    source_rows = [
        {
            "_time": "2026-08-06T09:00:00+00:00",
            "_raw": "Aug 06 09:00:00 host.example.test sshd: before",
        },
        inside,
        {"_raw": "Aug 06 10:01:00 host.example.test sshd: timeless"},
        {
            "_time": "not-a-time",
            "_raw": "Aug 06 10:02:00 host.example.test sshd: malformed",
        },
        {
            "_time": "2026-08-06T11:00:00+00:00",
            "_raw": "Aug 06 11:00:00 host.example.test sshd: after",
        },
    ]
    _install_fake_splunk(monkeypatch, [source_rows])

    rows, meta = fetch(
        {"spl": "search index=main"},
        {
            "host": "192.0.2.20",
            "port": 8089,
            "username": "user",
            "password": "pass",
        },
        since,
        until,
        False,
    )

    assert rows == [inside]
    assert meta["notes"] == [
        "dropped 2 rows without parseable _time values while enforcing the requested window"
    ]


def test_all_timeless_export_stays_nonempty_and_discloses_coarse_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    restore_display_utc,
) -> None:
    source_rows = [
        {"_raw": "Aug 06 09:45:00 host.example.test sshd: timeless"},
        {
            "_time": "not-a-time",
            "_raw": "Aug 06 10:15:00 host.example.test sshd: malformed",
        },
    ]
    _install_fake_splunk(monkeypatch, [source_rows])
    outpath = tmp_path / "auth.log"
    config = {
        "export": {
            "splunk": {
                "host": "192.0.2.20",
                "port": 8089,
                "username": "user",
                "password": "pass",
                "query": {"auth": {"spl": "search index=main"}},
            }
        }
    }

    run_export(
        config=config,
        backend="splunk",
        query_names=["auth"],
        since=datetime(2026, 8, 6, 9, 30, tzinfo=timezone.utc),
        until=datetime(2026, 8, 6, 10, 30, tzinfo=timezone.utc),
        out=str(outpath),
        verbose=False,
        use_utc=True,
    )

    assert len(outpath.read_text(encoding="utf-8").splitlines()) == 2
    rendered = capsys.readouterr().out
    assert "auth · 2 lines" in rendered
    assert "no parseable _time values" in rendered
    assert (
        "coarse window 2026-08-06 09:00 → 2026-08-06 11:00 UTC"
        in rendered
    )


# ── write ─────────────────────────────────────────────────────────────────────


def test_write_output(tmp_path: Path) -> None:
    rows = [
        {
            "_time": "2026-05-30T01:00:00.000+00:00",
            "_raw": "<34>May 30 01:00:00 192.0.2.10 kernel: boot message",
        },
        {
            "_time": "2026-05-29T23:00:00.000+00:00",
            "_raw": "May 29 23:00:00 192.0.2.11 sshd: no PRI prefix here",
        },
        {
            "_time": "2026-05-30T00:00:00.000+00:00",
            "_raw": "<5>May 30 00:00:00 192.0.2.10 nginx: another line",
        },
    ]
    outpath = tmp_path / "output.log"
    n, _ = write(rows, outpath, verbose=False)

    assert n == 3
    lines = outpath.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3

    # Sorted by _time ascending
    assert "May 29 23:00:00" in lines[0]
    assert "May 30 00:00:00" in lines[1]
    assert "May 30 01:00:00" in lines[2]

    # PRI prefixes stripped where present
    assert not lines[1].startswith("<")
    assert not lines[2].startswith("<")

    # Line without PRI written unchanged
    assert "no PRI prefix here" in lines[0]


def test_write_creates_parent_directories(tmp_path: Path) -> None:
    rows = [{"_time": "2026-05-30T01:00:00.000+00:00", "_raw": "May 30 01:00:00 192.0.2.10 kernel: boot"}]
    outpath = tmp_path / "a" / "b" / "out.log"
    n, _ = write(rows, outpath, verbose=False)
    assert n == 1
    assert outpath.exists()


# ── credentials ──────────────────────────────────────────────────────────────


def test_get_credentials_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIGWOOD_SPLUNK_USER", "testuser")
    monkeypatch.setenv("SIGWOOD_SPLUNK_PASS", "testpass")
    user, passwd = _get_credentials({})
    assert user == "testuser"
    assert passwd == "testpass"


def test_get_credentials_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIGWOOD_SPLUNK_USER", raising=False)
    monkeypatch.delenv("SIGWOOD_SPLUNK_PASS", raising=False)
    with pytest.raises(ValueError, match="Splunk credentials not found"):
        _get_credentials({})


# ── fetch SDK guard ───────────────────────────────────────────────────────────


def test_fetch_no_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    import sigwood.exporters.splunk as splunk_module

    monkeypatch.setattr(splunk_module, "splunk_client", None)
    since = datetime(2026, 5, 29, 0, 0, 0)
    until = datetime(2026, 5, 30, 0, 0, 0)
    with pytest.raises(ValueError, match="splunk-sdk not installed"):
        splunk_module.fetch(
            {"spl": "search *"},
            {"host": "192.0.2.20", "port": 8089, "username": "u", "password": "p"},
            since,
            until,
            False,
        )


def test_fetch_passes_verify_true_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    import sigwood.exporters.splunk as splunk_module

    captured: dict = {}

    class FakeJobs:
        @staticmethod
        def oneshot(*_args, **_kwargs):
            return object()

    class FakeService:
        jobs = FakeJobs()

    class FakeClient:
        @staticmethod
        def connect(**kwargs):
            captured.update(kwargs)
            return FakeService()

    class FakeResults:
        @staticmethod
        def JSONResultsReader(_job):
            return []

    monkeypatch.setattr(splunk_module, "splunk_client", FakeClient)
    monkeypatch.setattr(splunk_module, "splunk_results", FakeResults)

    splunk_module.fetch(
        {"spl": "search *"},
        {"host": "192.0.2.20", "port": 8089, "username": "u", "password": "p"},
        datetime(2026, 5, 29, 0, 0, 0),
        datetime(2026, 5, 29, 1, 0, 0),
        False,
    )

    assert captured["verify"] is True


def test_fetch_passes_verify_false_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    import sigwood.exporters.splunk as splunk_module

    captured: dict = {}

    class FakeJobs:
        @staticmethod
        def oneshot(*_args, **_kwargs):
            return object()

    class FakeService:
        jobs = FakeJobs()

    class FakeClient:
        @staticmethod
        def connect(**kwargs):
            captured.update(kwargs)
            return FakeService()

    class FakeResults:
        @staticmethod
        def JSONResultsReader(_job):
            return []

    monkeypatch.setattr(splunk_module, "splunk_client", FakeClient)
    monkeypatch.setattr(splunk_module, "splunk_results", FakeResults)

    splunk_module.fetch(
        {"spl": "search *"},
        {
            "host": "192.0.2.20",
            "port": 8089,
            "username": "u",
            "password": "p",
            "verify_tls": False,
        },
        datetime(2026, 5, 29, 0, 0, 0),
        datetime(2026, 5, 29, 1, 0, 0),
        False,
    )

    assert captured["verify"] is False


def test_fetch_rejects_non_bool_verify_tls_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sigwood.exporters.splunk as splunk_module

    class FakeClient:
        @staticmethod
        def connect(**_kwargs):
            raise AssertionError("connect must not be called")

    monkeypatch.setattr(splunk_module, "splunk_client", FakeClient)

    with pytest.raises(ValueError, match=r"\[export\.splunk\]\.verify_tls"):
        splunk_module.fetch(
            {"spl": "search *"},
            {
                "host": "192.0.2.20",
                "port": 8089,
                "username": "u",
                "password": "p",
                "verify_tls": "false",
            },
            datetime(2026, 5, 29, 0, 0, 0),
            datetime(2026, 5, 29, 1, 0, 0),
            False,
        )


def test_fetch_formats_splunk_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import sigwood.exporters.splunk as splunk_module

    class AuthenticationError(Exception):
        pass

    class FakeClient:
        @staticmethod
        def connect(**_kwargs):
            raise AuthenticationError("Login failed")

    monkeypatch.setattr(splunk_module, "splunk_client", FakeClient)
    since = datetime(2026, 5, 29, 0, 0, 0)
    until = datetime(2026, 5, 29, 1, 0, 0)

    with pytest.raises(ValueError) as exc_info:
        splunk_module.fetch(
            {"spl": "search *"},
            {"host": "192.0.2.20", "port": 8089, "username": "u", "password": "p"},
            since,
            until,
            False,
        )

    msg = str(exc_info.value)
    assert "Splunk login failed" in msg
    assert "SIGWOOD_SPLUNK_USER" in msg


def test_fetch_formats_splunk_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import sigwood.exporters.splunk as splunk_module

    class FakeClient:
        @staticmethod
        def connect(**_kwargs):
            raise OSError("connection refused")

    monkeypatch.setattr(splunk_module, "splunk_client", FakeClient)
    since = datetime(2026, 5, 29, 0, 0, 0)
    until = datetime(2026, 5, 29, 1, 0, 0)

    with pytest.raises(ValueError) as exc_info:
        splunk_module.fetch(
            {"spl": "search *"},
            {"host": "192.0.2.20", "port": 8089, "username": "u", "password": "p"},
            since,
            until,
            False,
        )

    msg = str(exc_info.value)
    assert "could not connect to Splunk management API" in msg
    assert "192.0.2.20:8089" in msg


def test_fetch_formats_tls_cert_verification_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A verify_tls handshake failure names the actual cause and the knob - never
    the generic host/port/credentials message (which points everywhere but the cert)."""
    import ssl

    import sigwood.exporters.splunk as splunk_module

    class FakeClient:
        @staticmethod
        def connect(**_kwargs):
            raise ssl.SSLCertVerificationError(
                1,
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                "self-signed certificate in certificate chain",
            )

    monkeypatch.setattr(splunk_module, "splunk_client", FakeClient)
    since = datetime(2026, 5, 29, 0, 0, 0)
    until = datetime(2026, 5, 29, 1, 0, 0)

    with pytest.raises(ValueError) as exc_info:
        splunk_module.fetch(
            {"spl": "search *"},
            {"host": "192.0.2.20", "port": 8089, "username": "u", "password": "p"},
            since,
            until,
            False,
        )

    msg = str(exc_info.value)
    assert "TLS certificate verification failed" in msg
    assert "192.0.2.20:8089" in msg
    assert "verify_tls = false" in msg
    assert "could not connect" not in msg


def test_sdk_error_message_detects_wrapped_cert_failure() -> None:
    """The cert-failure check walks the exception chain, so a wrapper that
    re-raises around the SSL error still gets the TLS message."""
    import ssl

    import sigwood.exporters.splunk as splunk_module

    inner = ssl.SSLCertVerificationError(1, "certificate verify failed")
    try:
        try:
            raise inner
        except ssl.SSLCertVerificationError as e:
            raise RuntimeError("wrapped by a transport layer") from e
    except RuntimeError as wrapper:
        msg = splunk_module._sdk_error_message(wrapper, "192.0.2.20", 8089)
    assert "TLS certificate verification failed" in msg
    assert "verify_tls = false" in msg


def test_default_splunk_export_dir_is_global_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """No shipped Splunk query - user must define one. The cascade still
    resolves an empty / synthetic query against the shipped global export_dir
    (tier 4: ~/.sigwood/exports), which auto-segments per source."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [tmp_path / "missing.toml"])
    config = cfg.load(config_file=None)
    user_query = {"output_basename": "syslog"}   # user-defined query - minimum shape
    since = datetime(2026, 5, 30, 0, 0, 0)
    until = datetime(2026, 5, 31, 0, 0, 0)

    result = _resolve_output_path(
        user_query, None, since, until, "default",
        backend_config=config["export"]["splunk"],
        sigwood_config=config["sigwood"],
        root=effective_root(config),
    )

    assert result.parent == Path("~/.sigwood/exports/syslog").expanduser()


# ── query resolution ──────────────────────────────────────────────────────────


def _make_config(queries: dict) -> dict:
    return {"export": {"splunk": {"host": "192.0.2.20", "port": 8089, "query": queries}}}


def test_query_resolution_default() -> None:
    config = _make_config({"default": {"spl": "search *"}})
    result = _resolve_queries(config, "splunk", [])
    assert result == [("default", {"spl": "search *"})]


def test_query_resolution_single() -> None:
    config = _make_config({"myquery": {"spl": "search index=main"}})
    result = _resolve_queries(config, "splunk", [])
    assert result == [("myquery", {"spl": "search index=main"})]


def test_query_resolution_ambiguous() -> None:
    config = _make_config({"alpha": {"spl": "search a"}, "beta": {"spl": "search b"}})
    with pytest.raises(ValueError) as exc_info:
        _resolve_queries(config, "splunk", [])
    assert str(exc_info.value) == (
        "multiple queries for backend 'splunk': alpha, beta - "
        "specify one: sigwood export splunk <query>"
    )


def test_query_resolution_default_among_multiple_is_ambiguous() -> None:
    config = _make_config({
        "default": {"spl": "search index=main"},
        "auth": {"spl": "search index=auth"},
    })
    with pytest.raises(ValueError) as exc_info:
        _resolve_queries(config, "splunk", [])
    assert str(exc_info.value) == (
        "multiple queries for backend 'splunk': auth, default - "
        "specify one: sigwood export splunk <query>"
    )


def test_query_resolution_zero_is_byte_stable() -> None:
    with pytest.raises(ValueError) as exc_info:
        _resolve_queries(_make_config({}), "splunk", [])
    assert str(exc_info.value) == (
        "no queries defined under [export.splunk.query] - "
        "add a [export.splunk.query.<name>] section"
    )


def test_query_resolution_explicit() -> None:
    config = _make_config({
        "auth": {"spl": "search a"},
        "default": {"spl": "search d"},
    })
    result = _resolve_queries(config, "splunk", ["default"])
    assert result == [("default", {"spl": "search d"})]


def test_query_resolution_missing() -> None:
    config = _make_config({"alpha": {"spl": "search a"}})
    with pytest.raises(ValueError, match="noexist"):
        _resolve_queries(config, "splunk", ["noexist"])


# ── output path resolution ────────────────────────────────────────────────────


def test_output_autoname_single_day(tmp_path: Path) -> None:
    """cli_out is now a string; tmp_path exists -> Step 2 DIRECTORY verdict."""
    since = datetime(2026, 5, 30, 0, 0, 0)
    until = datetime(2026, 5, 31, 0, 0, 0)  # exactly 1 day
    query_cfg = {"output_basename": "syslog"}
    result = _resolve_output_path(query_cfg, str(tmp_path), since, until, "default")
    assert result.name == "syslog_20260530_1d.log"
    assert result.parent == tmp_path


def test_output_autoname_multi_day(tmp_path: Path) -> None:
    since = datetime(2026, 5, 24, 0, 0, 0)
    until = datetime(2026, 5, 31, 0, 0, 0)  # exactly 7 days
    query_cfg = {"output_basename": "syslog"}
    result = _resolve_output_path(query_cfg, str(tmp_path), since, until, "default")
    assert result.name == "syslog_20260524_7d.log"
    assert result.parent == tmp_path


def test_output_explicit_path(tmp_path: Path) -> None:
    """A non-existent path with no trailing slash -> Step 3 FILE verdict."""
    since = datetime(2026, 5, 30, 0, 0, 0)
    until = datetime(2026, 5, 31, 0, 0, 0)
    explicit = tmp_path / "myfile.log"
    assert not explicit.exists()
    result = _resolve_output_path({}, str(explicit), since, until, "default")
    assert result == explicit
