"""Tests for the syslog parser (parsers/syslog.py) and load_syslog() integration."""

from __future__ import annotations

import bz2
import gzip
import lzma
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigwood.common.loader import (
    _stem_hostname,
    load_required_logs,
    load_syslog,
)
from sigwood.common.display import fmt_timestamp
from sigwood.parsers.syslog import (
    is_reboot_signal,
    parse_program,
    parse_timestamp,
    strip_header,
)


# ── parse_timestamp ────────────────────────────────────────────────────────────

def test_parse_timestamp_year_rollback() -> None:
    """A timestamp 10 days in the future is rolled back to the previous year."""
    future = (datetime.now(timezone.utc) + timedelta(days=10)).replace(
        hour=12, minute=0, second=0, microsecond=0
    )
    raw = f"<134>{future.strftime('%b')} {future.day} 12:00:00 router sshd: message"
    result = parse_timestamp(raw)
    assert result is not None
    assert result == future.replace(year=future.year - 1)


def test_parse_timestamp_returns_utc_aware() -> None:
    result = parse_timestamp("<134>May 31 12:00:00 router sshd: message")
    assert result is not None
    assert result.tzinfo == timezone.utc


def test_parse_timestamp_unparseable_returns_none() -> None:
    assert parse_timestamp("not a valid syslog line at all") is None


# ── parse_timestamp: host-local wall-clock interpretation ─────────────────────
#
# Timestamps derive from the runtime clock (RFC 3164 carries no year - a
# literal date would rot). Expected instants are computed in-test AFTER the TZ
# pin is active, never by parse_timestamp itself.

def _stamp(dt: datetime) -> str:
    """RFC 3164 stamp (space-padded day) for a derived wall-clock datetime."""
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


def test_parse_timestamp_wallclock_is_host_local(pin_tz) -> None:
    """The RFC 3164 wall-clock is interpreted in the host's local timezone."""
    pin_tz("Etc/GMT+6")  # POSIX sign inversion: UTC-6, fixed offset, no DST
    local_naive = (datetime.now() - timedelta(days=30)).replace(
        second=0, microsecond=0
    )
    raw = f"<134>{_stamp(local_naive)} router sshd[100]: session opened"
    result = parse_timestamp(raw)
    assert result is not None
    assert result == local_naive.astimezone(timezone.utc)


def test_parse_timestamp_utc_box_unchanged(pin_tz) -> None:
    """On a UTC box local == UTC: the result equals the wall-clock stamped UTC."""
    pin_tz("UTC")
    local_naive = (datetime.now() - timedelta(days=30)).replace(
        second=0, microsecond=0
    )
    raw = f"<134>{_stamp(local_naive)} router sshd[100]: session opened"
    result = parse_timestamp(raw)
    assert result is not None
    assert result == local_naive.replace(tzinfo=timezone.utc)


def test_parse_timestamp_year_rollback_local_space(pin_tz) -> None:
    """The +7d rollback operates on local wall-clock values under a non-UTC zone."""
    pin_tz("Etc/GMT+6")
    future = (datetime.now() + timedelta(days=8)).replace(
        hour=12, minute=0, second=0, microsecond=0
    )
    raw = f"<134>{_stamp(future)} router sshd[100]: session opened"
    result = parse_timestamp(raw)
    assert result is not None
    assert result == future.replace(year=future.year - 1).astimezone(timezone.utc)


def test_parse_timestamp_fmt_timestamp_round_trip(pin_tz) -> None:
    """End-to-end honesty: the wall-clock the log said is what the reader sees."""
    pin_tz("Etc/GMT+6")
    local_naive = (datetime.now() - timedelta(days=30)).replace(
        second=0, microsecond=0
    )
    raw = f"<134>{_stamp(local_naive)} router sshd[100]: session opened"
    result = parse_timestamp(raw)
    assert result is not None
    assert fmt_timestamp(result) == f"{local_naive:%Y-%m-%d %H:%M} local"


# ── is_reboot_signal ───────────────────────────────────────────────────────────

def test_is_reboot_signal_logind_reboot() -> None:
    line = "<165>May 31 06:00:00 router systemd-logind[42]: System is rebooting."
    assert is_reboot_signal(line) is True


def test_is_reboot_signal_rsyslogd_exit() -> None:
    line = "<165>May 31 06:00:00 router rsyslogd: exiting on signal 15."
    assert is_reboot_signal(line) is True


def test_is_reboot_signal_kernel_boot_banner() -> None:
    """The kernel boot banner is recognized with OR without a ring-buffer ts
    prefix (`kernel: [    0.000000] Linux version …`, verified on real data)."""
    plain = "<6>May 30 00:00:00 host kernel: Linux version 6.1.0"
    ringbuf = "<6>May 30 00:00:00 host kernel: [    0.000000] Linux version 6.1.0"
    assert is_reboot_signal(plain) is True
    assert is_reboot_signal(ringbuf) is True


def test_is_reboot_signal_false_for_normal_line() -> None:
    line = "<134>May 31 12:00:00 router sshd[1234]: Accepted publickey for user"
    assert is_reboot_signal(line) is False


# ── parse_program ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "body, expected",
    [
        ("sshd[1234]: Accepted publickey", "sshd"),
        ("postfix/smtpd[889]: connect from", "postfix/smtpd"),
        ("kernel: Linux version 6.1", "kernel"),
        ("audisp: node=... type=...", "audisp"),
        ("", "unknown"),
        ("   ", "unknown"),
        (": payload", "unknown"),
        ("[123]: payload", "unknown"),
    ],
)
def test_parse_program(body: str, expected: str) -> None:
    """parse_program returns the leading non-whitespace token before '[' or ':',
    falling back to 'unknown' when no such token exists."""
    assert parse_program(body) == expected


# ── load_syslog ────────────────────────────────────────────────────────────────

def test_load_syslog_per_host_files(tmp_path: Path) -> None:
    """Two per-host files: H4 reads the in-content RFC-3164 host (which here
    equals the filename stem), correct schema, correct row count. Both files
    pass the content-sniff gate (real RFC-3164 lines)."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "router.log").write_text(
        "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user\n"
        "<134>May 31 12:01:00 router sshd[101]: session opened for user\n",
        encoding="utf-8",
    )
    (syslog_dir / "webserver.log").write_text(
        "<134>May 31 12:02:00 webserver nginx[200]: GET / HTTP/1.1 200\n",
        encoding="utf-8",
    )

    df = load_syslog(syslog_dir)

    assert list(df.columns) == ["ts", "host", "program", "raw", "message"]
    assert len(df) == 3
    assert set(df["host"]) == {"router", "webserver"}
    assert (df[df["host"] == "router"]["host"] == "router").all()
    assert (df[df["host"] == "webserver"]["host"] == "webserver").all()
    assert set(df[df["host"] == "router"]["program"]) == {"sshd"}
    assert df[df["host"] == "webserver"]["program"].iloc[0] == "nginx"
    # Lock the byte-identical `message` invariant directly at this surface -
    # adding `program` must not perturb the drain3 input.
    assert set(df[df["host"] == "router"]["message"]) == {
        "sshd[*]: Accepted publickey for user",
        "sshd[*]: session opened for user",
    }


def test_load_syslog_non_host_filename_reads_in_content_host(tmp_path: Path) -> None:
    """A file named with a non-host stem (syslog.log): H4 reads the in-content
    host per line - no filename inheritance."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "syslog.log").write_text(
        "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user\n"
        "<134>May 31 12:01:00 webserver nginx[200]: GET / HTTP/1.1 200\n",
        encoding="utf-8",
    )

    df = load_syslog(syslog_dir)

    assert list(df.columns) == ["ts", "host", "program", "raw", "message"]
    assert len(df) == 2
    assert set(df["host"]) == {"router", "webserver"}


def test_load_syslog_multi_host_dump_keeps_distinct_in_content_hosts(tmp_path: Path) -> None:
    """A multi-host flat dump named with a non-host stem (syslog.2M.log): H4
    reads the distinct in-content hosts per line - nothing collapses to the
    filename (a whole-stem host inheritance would collapse them to the stem)."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "syslog.2M.log").write_text(
        "<134>May 31 12:00:00 routerA sshd[100]: Accepted publickey for user\n"
        "<134>May 31 12:01:00 webserverB nginx[200]: GET / HTTP/1.1 200\n"
        "<134>May 31 12:02:00 dbhostC cron[300]: (root) CMD (placeholder)\n",
        encoding="utf-8",
    )

    df = load_syslog(syslog_dir)

    assert len(df) == 3
    assert set(df["host"]) == {"routerA", "webserverB", "dbhostC"}


def test_load_syslog_hostless_line_falls_back_to_filename_stem(tmp_path: Path) -> None:
    """H4 fallback: a genuinely hostless line (parse_host → "unknown", <4 tokens)
    takes the filename stem. Exercised on an EXPLICIT FILE input - the gate is
    bypassed for a named file, and a directory file would have to pass the
    RFC-3164 gate (a gate-passing line almost always yields a non-"unknown"
    host, so the fallback arm is not reachable from directory discovery)."""
    f = tmp_path / "relay1.log"
    f.write_text("boot sequence done\n", encoding="utf-8")

    df = load_syslog(f)

    assert len(df) == 1
    assert df.iloc[0]["host"] == "relay1"


def test_load_syslog_unparseable_timestamps_produce_nan_not_dropped(tmp_path: Path) -> None:
    """Lines with no parseable timestamp produce ts=nan and are kept in the DataFrame."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "router.log").write_text(
        "not a valid syslog line at all\n"
        "<134>May 31 12:00:00 192.0.2.1 sshd[100]: normal line\n",
        encoding="utf-8",
    )

    df = load_syslog(syslog_dir)

    assert len(df) == 2
    nan_rows = df[df["ts"].isna()]
    assert len(nan_rows) == 1


# ── load_required_logs() wiring ────────────────────────────────────────────────

def test_load_syslog_with_single_file(tmp_path: Path) -> None:
    """load_syslog() accepts a single file path in place of a directory."""
    log_file = tmp_path / "router.log"
    log_file.write_text(
        "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user\n",
        encoding="utf-8",
    )
    df = load_syslog(log_file)
    assert list(df.columns) == ["ts", "host", "program", "raw", "message"]
    assert len(df) == 1
    assert df.iloc[0]["host"] == "router"


def test_load_syslog_directory_silently_drops_ndjson(tmp_path: Path, capsys) -> None:
    """A wrong-family NDJSON in a syslog DIRECTORY is dropped by the content-sniff
    gate - silently, at EVERY verbosity (decision C: no per-file stderr for
    rejected candidates). The real syslog file still loads."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "conn.log").write_text(
        '{"ts": 1.0, "id.orig_h": "192.0.2.1"}\n', encoding="utf-8"
    )
    (syslog_dir / "router.log").write_text(
        "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user\n",
        encoding="utf-8",
    )
    df = load_syslog(syslog_dir)
    assert len(df) == 1
    assert capsys.readouterr().err == ""

    df = load_syslog(syslog_dir, verbose=True)
    assert len(df) == 1
    assert "conn.log" not in capsys.readouterr().err


def test_load_syslog_explicit_ndjson_file_skipped_and_warns(tmp_path: Path, capsys) -> None:
    """An EXPLICITLY-NAMED NDJSON file bypasses the gate (operator intent) but is
    skipped by `_syslog_should_skip` at load; the skip note reaches stderr ONLY
    in verbose mode."""
    f = tmp_path / "conn.log"
    f.write_text('{"ts": 1.0, "id.orig_h": "192.0.2.1"}\n', encoding="utf-8")

    df = load_syslog(f)
    assert len(df) == 0
    assert capsys.readouterr().err == ""

    df = load_syslog(f, verbose=True)
    assert len(df) == 0
    captured = capsys.readouterr()
    assert "conn.log" in captured.err
    assert "NDJSON" in captured.err


def test_stem_hostname_variants() -> None:
    """_stem_hostname strips log suffixes and rotation numbers, preserving dotted hostnames."""
    assert _stem_hostname("router.log") == "router"
    assert _stem_hostname("router.log.gz") == "router"
    assert _stem_hostname("host1.example.com.log") == "host1.example.com"
    assert _stem_hostname("syslog.log.1") == "syslog"


def test_load_required_logs_routes_syslog_dir(tmp_path: Path) -> None:
    """load_required_logs() branches on syslog_dir and returns the syslog schema."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "router.log").write_text(
        "<134>May 31 12:00:00 192.0.2.1 sshd[100]: Accepted publickey for user\n",
        encoding="utf-8",
    )

    result = load_required_logs(
        {"*": "syslog_dir"},
        {"syslog_dir": [syslog_dir]},
    )

    assert "*" in result.logs
    df = result.logs["*"]
    assert list(df.columns) == ["ts", "host", "program", "raw", "message"]
    assert len(df) == 1
    assert result.record_counts == {"*": 1}
    assert result.warnings == []


# ── strip_header doubled-timestamp invariant ──────────────────────────────────

def test_strip_header_preserves_inner_timestamp_in_body() -> None:
    """SYSLOG_HDR_RE is `^`-anchored: only the LEADING transport header is
    stripped; an app's own inner RFC 3164-shaped timestamp in the body
    survives verbatim. This invariant is critical for the Zeek syslog.log
    normalizer - both feeds share strip_header, so any regression here would
    misderive `program`/`message` on either path."""
    raw = "Jan 02 03:04:05 host1 prog: payload Jan 02 03:04:05 host2 prog2: inner"
    stripped = strip_header(raw)
    assert stripped == "prog: payload Jan 02 03:04:05 host2 prog2: inner"


def test_strip_header_idempotent_when_no_leading_header() -> None:
    """A body that does NOT begin with a transport header is returned unchanged
    (modulo PRI prefix stripping, which is absent here too)."""
    raw = "prog: body without any leading transport header"
    assert strip_header(raw) == "prog: body without any leading transport header"


# ── load_syslog defensive Zeek-TSV skip (gated on #separator) ─────────────────

def test_load_syslog_directory_silently_drops_zeek_tsv(tmp_path: Path, capsys) -> None:
    """A Zeek-TSV syslog.log in a syslog DIRECTORY is dropped by the content-sniff
    gate (no RFC-3164 header line) - silently, at EVERY verbosity. The real
    syslog file still loads, not garbled into NaN-ts rows."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "syslog.log").write_text(
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#path\tsyslog\n"
        "#fields\tts\thost\tmessage\n"
        "#types\ttime\tstring\tstring\n"
        "1779750000.0\thost1\tplaceholder\n",
        encoding="utf-8",
    )
    (syslog_dir / "router.log").write_text(
        "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user\n",
        encoding="utf-8",
    )

    df = load_syslog(syslog_dir)
    assert len(df) == 1
    assert capsys.readouterr().err == ""

    df = load_syslog(syslog_dir, verbose=True)
    assert len(df) == 1
    assert "syslog.log" not in capsys.readouterr().err


def test_load_syslog_explicit_zeek_tsv_file_skipped_and_warns(tmp_path: Path, capsys) -> None:
    """An EXPLICITLY-NAMED Zeek-TSV file bypasses the gate but is skipped by
    `_syslog_should_skip` at load - the gate is narrow on the `#separator`
    directive (the exact signal the Zeek strategy parse uses). Verbose mode
    emits an actionable note pointing at zeek_dir."""
    f = tmp_path / "syslog.log"
    f.write_text(
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#path\tsyslog\n"
        "#fields\tts\thost\tmessage\n"
        "#types\ttime\tstring\tstring\n"
        "1779750000.0\thost1\tplaceholder\n",
        encoding="utf-8",
    )

    df = load_syslog(f)
    assert len(df) == 0
    assert capsys.readouterr().err == ""

    df = load_syslog(f, verbose=True)
    assert len(df) == 0
    captured = capsys.readouterr()
    assert "syslog.log" in captured.err
    assert "Zeek TSV" in captured.err
    assert "zeek_dir" in captured.err


def test_load_syslog_does_not_skip_hash_comment_flat_syslog(tmp_path: Path) -> None:
    """An ordinary `#`-comment-bearing flat syslog file is NOT skipped - the
    Zeek-TSV gate is narrow on `#separator`, not generic `#`. Regression check
    for the gate-narrowness rail. (Explicit file → gate bypassed; should_skip
    must still not skip it.)"""
    f = tmp_path / "router.log"
    f.write_text(
        "# this is a leading comment, not a Zeek header\n"
        "# another comment\n"
        "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user\n",
        encoding="utf-8",
    )

    df = load_syslog(f)
    assert len(df) == 1
    assert df.iloc[0]["host"] == "router"


# ── bz2 / xz transparent decompression at load_syslog ────────────────────────
#
# A rotated `system.log.bz2` in `/var/log` must NOT read as replacement-char
# garbage (which would title findings with binary soup): with bz2/xz in
# `_open_log`, the public `load_syslog` path ingests it as text rows like any
# other syslog file.

_SYSLOG_BZ2_XZ_LINES = (
    "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user\n"
    "<134>May 31 12:01:00 router sshd[101]: session opened for user\n"
)


def test_load_syslog_decompresses_bz2(tmp_path: Path) -> None:
    """A rotated `system.log.bz2` ingests as text rows - no binary soup.

    `system` is a generic stem, so per-line `parse_host` runs and recovers
    the embedded `router` host from the fixture lines. The required
    invariant is that the rows render as TEXT, not as bzip2-magic / soup.
    """
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "system.log.bz2").write_bytes(
        bz2.compress(_SYSLOG_BZ2_XZ_LINES.encode("utf-8"))
    )

    df = load_syslog(syslog_dir)

    assert len(df) == 2
    assert set(df["host"]) == {"router"}
    assert set(df["program"]) == {"sshd"}
    # Sanity: no bzip2-magic / replacement-char soup leaked into the title-feed.
    assert not any("BZh" in r for r in df["raw"])
    assert not any("�" in r for r in df["raw"])


def test_load_syslog_decompresses_xz(tmp_path: Path) -> None:
    """The xz sibling - same shape as bz2 above."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "messages.log.xz").write_bytes(
        lzma.compress(_SYSLOG_BZ2_XZ_LINES.encode("utf-8"))
    )

    df = load_syslog(syslog_dir)

    assert len(df) == 2
    assert set(df["host"]) == {"router"}
    assert set(df["program"]) == {"sshd"}
    # No xz-magic byte (`\xfd7zXZ`) bytes in the raw text.
    assert not any("7zXZ" in r for r in df["raw"])
    assert not any("�" in r for r in df["raw"])


# ── load_syslog: corrupt compressed-file skip-with-warning ──────────────────
#
# `_open_log` is lazy - corrupt compressed files raise at the READ site, not
# the open. The flat-syslog reader catches the decode-error family per-file,
# emits the standard read-warning, and continues so one bad file never aborts
# the load. `lzma.LZMAError` is NOT an `OSError` - without the explicit
# catch, a corrupt `.xz` would leak past the CLI as a raw traceback.


@pytest.mark.parametrize("suffix, corrupt_bytes", [
    (".gz",  b"NOTGZIP garbage"),
    (".bz2", b"NOTBZIP2 garbage"),
    (".xz",  b"NOTXZ garbage"),
])
def test_load_syslog_corrupt_compressed_file_skipped_with_warning(
    tmp_path: Path, suffix: str, corrupt_bytes: bytes,
) -> None:
    """A corrupt compressed file is skipped per-file with the actionable
    read-warning. Good files in the same directory still load (skip is
    per-file, not whole-run). The phrasing differs by corruption shape -
    .gz/.xz land in the "incomplete or corrupt" branch, .bz2's OSError
    falls to the generic class-name fallback; both branches satisfy the
    contract of "warned, not traceback'd"."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    # Good companion file alongside the corrupt one.
    (syslog_dir / "router.log").write_text(
        "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user\n",
        encoding="utf-8",
    )
    (syslog_dir / f"system.log{suffix}").write_bytes(corrupt_bytes)

    warnings: list[str] = []
    df = load_syslog(syslog_dir, _warnings=warnings)

    # Good file still loaded.
    assert len(df) == 1
    assert df.iloc[0]["host"] == "router"
    # Corrupt file produced an actionable warning, not a traceback.
    assert any(
        f"system.log{suffix} could not be read" in w for w in warnings
    )


def test_load_syslog_corrupt_xz_lands_in_incomplete_or_corrupt_branch(
    tmp_path: Path,
) -> None:
    """The wrinkle assertion: a corrupt `.xz` lands in
    `_zeek_file_read_warning`'s "compressed file is incomplete or corrupt"
    branch, NOT the generic class-name fallback. Proves `lzma.LZMAError` is
    recognised at the warning helper, not just caught at the loop."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "system.log.xz").write_bytes(b"NOTXZ garbage")

    warnings: list[str] = []
    load_syslog(syslog_dir, _warnings=warnings)

    assert any(
        "system.log.xz could not be read" in w and "incomplete or corrupt" in w
        for w in warnings
    )


def test_load_syslog_corrupt_compressed_file_without_warnings_buffer(
    tmp_path: Path,
) -> None:
    """When _warnings is None (notebook callers, direct library use), a corrupt
    file still doesn't raise - it's silently skipped. Locks the warnings=None
    branch so a future tightening can't turn this into a regression."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "system.log.xz").write_bytes(b"NOTXZ garbage")

    df = load_syslog(syslog_dir)  # _warnings omitted
    assert df.empty


# ── load_syslog: truncated (trailer-corrupt) compressed file honesty rail ──
#
# Invalid-magic corruption raises immediately on read. Truncated compressed
# files are nastier: the decompressor yields valid-looking lines and only
# raises at the EOF/trailer check. Pre-honesty-fix, a file the loader warned
# it had "skipped" still leaked rows into the returned frame.
# Honesty rail: a file the loader warns it skipped contributes ZERO rows.

_SYSLOG_TRUNCATE_PAYLOAD = (
    "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user a\n"
    "<134>May 31 12:01:00 router sshd[101]: Accepted publickey for user b\n"
    "<134>May 31 12:02:00 router sshd[102]: Accepted publickey for user c\n"
    "<134>May 31 12:03:00 router sshd[103]: Accepted publickey for user d\n"
    "<134>May 31 12:04:00 router sshd[104]: Accepted publickey for user e\n"
    "<134>May 31 12:05:00 router sshd[105]: Accepted publickey for user f\n"
    "<134>May 31 12:06:00 router sshd[106]: Accepted publickey for user g\n"
    "<134>May 31 12:07:00 router sshd[107]: Accepted publickey for user h\n"
    "<134>May 31 12:08:00 router sshd[108]: Accepted publickey for user i\n"
    "<134>May 31 12:09:00 router sshd[109]: Accepted publickey for user j\n"
    "<134>May 31 12:10:00 router sshd[110]: Accepted publickey for user k\n"
    "<134>May 31 12:11:00 router sshd[111]: Accepted publickey for user l\n"
    "<134>May 31 12:12:00 router sshd[112]: Accepted publickey for user m\n"
    "<134>May 31 12:13:00 router sshd[113]: Accepted publickey for user n\n"
    "<134>May 31 12:14:00 router sshd[114]: Accepted publickey for user o\n"
    "<134>May 31 12:15:00 router sshd[115]: Accepted publickey for user p\n"
    "<134>May 31 12:16:00 router sshd[116]: Accepted publickey for user q\n"
    "<134>May 31 12:17:00 router sshd[117]: Accepted publickey for user r\n"
    "<134>May 31 12:18:00 router sshd[118]: Accepted publickey for user s\n"
    "<134>May 31 12:19:00 router sshd[119]: Accepted publickey for user t\n"
)


def _truncated_compressed(payload: bytes, suffix: str) -> bytes:
    """Compress ``payload`` with the suffix's algorithm and lop off the last
    byte so the trailer fails. The decompressor yields valid-looking lines
    until it hits the broken trailer, then raises."""
    if suffix == ".gz":
        return gzip.compress(payload)[:-1]
    if suffix == ".bz2":
        return bz2.compress(payload)[:-1]
    if suffix == ".xz":
        return lzma.compress(payload)[:-1]
    raise ValueError(f"unsupported suffix {suffix!r}")


@pytest.mark.parametrize("suffix", [".gz", ".bz2", ".xz"])
def test_load_syslog_trailer_corrupt_compressed_contributes_zero_rows(
    tmp_path: Path, suffix: str,
) -> None:
    """A truncated `.gz` / `.bz2` / `.xz` syslog file: the warning fires AND
    the corrupt file contributes ZERO rows. A good companion file in the
    same directory still loads (skip is per-file, not whole-run)."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    # Good companion - exactly one identifiable line.
    (syslog_dir / "router.log").write_text(
        "<134>May 31 23:59:00 router sshd[999]: Accepted publickey for COMPANION\n",
        encoding="utf-8",
    )
    (syslog_dir / f"system.log{suffix}").write_bytes(
        _truncated_compressed(_SYSLOG_TRUNCATE_PAYLOAD.encode("utf-8"), suffix)
    )

    warnings: list[str] = []
    df = load_syslog(syslog_dir, _warnings=warnings)

    # The corrupt file produced a warning…
    assert any(
        f"system.log{suffix} could not be read" in w for w in warnings
    )
    # …AND contributed zero rows. The good companion's single row is the
    # ONLY row in the frame. Pre-honesty-fix, the truncated file's pre-EOF
    # rows leaked in here too.
    assert len(df) == 1
    assert "COMPANION" in df.iloc[0]["raw"]
