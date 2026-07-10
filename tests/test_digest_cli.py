"""Stage 3 fan-out behavior for ``sigwood digest`` - schema-agnostic tests.

The per-schema digest test files own single-path CLI routing; this file owns
the cross-schema fan-out contract: N positionals digested independently,
per-path outcomes (rendered / empty / error) tallied to a three-way exit
code, and a shared ``--out`` target receiving concatenated cards.
"""

from __future__ import annotations

import io
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

import sigwood.cli as cli
import sigwood.runner as runner
from sigwood.common.display import default_window_advisory


# ─── Fixtures - single representative line per schema ───────────────────────

_ZEEK_NDJSON_CONN_LINE = (
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",'
    ' "id.resp_p": 443, "proto": "tcp", "duration": 1.23}\n'
)
_ZEEK_DNS_NDJSON_LINE = (
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", "query": "example.test"}\n'
)
_PIHOLE_LINE = (
    "Jun  1 12:00:00 piholehost dnsmasq[123]: query[A] example.test from 192.0.2.10\n"
)
_SYSLOG_LINE = (
    "<13>Jun  1 12:00:00 examplehost sshd[1234]: Accepted publickey for placeholder\n"
)
_BLOB_LINE = (
    "totally-unrecognized-application-banner xyzzy 42 frobnicate\n"
)


def _stub_config(monkeypatch, cfg_dict: dict | None = None) -> None:
    monkeypatch.setattr(cli.cfg, "load", lambda _p: cfg_dict or {"sigwood": {}})


def _spy_run_digest_calls(monkeypatch) -> list[dict[str, Any]]:
    """Replace runner.run_digest with a spy that records every call's kwargs."""
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(runner, "run_digest", lambda **kwargs: calls.append(kwargs))
    return calls


# ─── Fan-out: multiple positionals digested in order ────────────────────────


def test_digest_three_mixed_positionals_render_in_argv_order(
    tmp_path: Path, monkeypatch,
) -> None:
    """Three positionals of mixed formats → three run_digest calls, each
    routed to the source-dir kwarg matching its sniffed schema."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    dns = tmp_path / "dns.log"
    dns.write_text(_ZEEK_DNS_NDJSON_LINE, encoding="utf-8")
    syslog = tmp_path / "syslog.log"
    syslog.write_text(_SYSLOG_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(conn), str(dns), str(syslog)])

    assert rc == 0
    assert [c["schema"] for c in calls] == ["conn", "dns", "syslog"]
    assert calls[0]["zeek_dir"] == str(conn)
    assert calls[1]["zeek_dir"] == str(dns)
    assert calls[2]["syslog_dir"] == str(syslog)


def test_digest_pihole_positional_routes_to_pihole_dir_in_fanout(
    tmp_path: Path, monkeypatch,
) -> None:
    """A dnsmasq/Pi-hole line in a fan-out gets the ``pihole_dir`` route, not
    ``zeek_dir`` - Stage 1/2 origin distinction survives the loop."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    zeek_dns = tmp_path / "zeek_dns.log"
    zeek_dns.write_text(_ZEEK_DNS_NDJSON_LINE, encoding="utf-8")
    pihole = tmp_path / "pihole.log"
    pihole.write_text(_PIHOLE_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(zeek_dns), str(pihole)])

    assert rc == 0
    assert len(calls) == 2
    assert calls[0]["schema"] == "dns" and calls[0]["zeek_dir"] == str(zeek_dns)
    assert calls[1]["schema"] == "dns" and calls[1]["pihole_dir"] == str(pihole)


# ─── -q / quiet threading into run_digest ────────────────────────────────────


def test_digest_quiet_from_config_threads_into_run_digest(
    tmp_path: Path, monkeypatch,
) -> None:
    """[sigwood].quiet = true with NO -q must reach run_digest as quiet=True.
    A single positional passes show_progress=True (is_multirun=False); the
    runner combines them - both inputs are present on the call."""
    _stub_config(monkeypatch, {"sigwood": {"quiet": True}})
    calls = _spy_run_digest_calls(monkeypatch)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(conn)])

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["quiet"] is True
    assert calls[0]["show_progress"] is True  # single positional → not is_multirun


def test_digest_quiet_flag_threads_into_run_digest(
    tmp_path: Path, monkeypatch,
) -> None:
    """`-q` on the CLI reaches run_digest as quiet=True over config-default."""
    _stub_config(monkeypatch)  # no quiet in config
    calls = _spy_run_digest_calls(monkeypatch)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", "-q", str(conn)])

    assert rc == 0
    assert calls[0]["quiet"] is True


def test_digest_quiet_absent_defaults_false(
    tmp_path: Path, monkeypatch,
) -> None:
    """No -q, no config quiet → run_digest receives quiet=False."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    cli._main(["digest", str(conn)])
    assert calls[0]["quiet"] is False


# ─── Three-way exit policy ───────────────────────────────────────────────────


def test_digest_mixed_valid_empty_missing_renders_and_exits_zero(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """1 valid + 1 empty + 1 missing → valid card renders, empty prints its
    line on stdout, missing prints its error on stderr, exit 0 (≥1 rendered)."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    missing = tmp_path / "missing.log"  # never created

    rc = cli._main(["digest", str(conn), str(empty), str(missing)])

    captured = capsys.readouterr()
    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["schema"] == "conn"
    assert "empty.log is empty - nothing to do" in captured.out
    assert "not found" in captured.err


def test_digest_all_empty_exits_zero(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """2 empty files, no valid, no missing → both "Nothing to do!" lines,
    exit 0 (empty is not a failure)."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    a = tmp_path / "a.log"
    a.write_text("", encoding="utf-8")
    b = tmp_path / "b.log"
    b.write_text("", encoding="utf-8")

    rc = cli._main(["digest", str(a), str(b)])

    captured = capsys.readouterr()
    assert rc == 0
    assert calls == []
    assert captured.out.count("nothing to do") == 2


def test_digest_all_error_exits_nonzero(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Missing path in a multi-path fan-out → error on stderr, exit 1.

    Note: a directory positional in multi-path is silently skipped - see
    test_digest_multipath_directory_is_silently_skipped. This test isolates
    the missing-path error path, which retains its stderr message.
    """
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    other = tmp_path / "also_missing.log"

    rc = cli._main(["digest", "/no/such/file.log", str(other)])

    captured = capsys.readouterr()
    assert rc == 1
    assert calls == []
    assert "not found" in captured.err


def test_digest_mixed_empty_and_error_no_render_exits_nonzero(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Mixed empty + error, no card rendered → exit 1 (a real error is present)."""
    _stub_config(monkeypatch)
    _spy_run_digest_calls(monkeypatch)

    empty = tmp_path / "e.log"
    empty.write_text("", encoding="utf-8")

    rc = cli._main(["digest", str(empty), "/no/such/file.log"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "nothing to do" in captured.out
    assert "not found" in captured.err


# ─── Directory positionals: silent skip in fan-out, error on lone ───────────
#
# A directory positional in shell-expanded multi-path fan-out should not
# interleave error noise between cards. The v1 contract for a lone-directory
# positional (single positional, hits a directory) stays - actionable stderr
# message and exit 1. Other per-path errors (missing path, sniff failure)
# continue to surface in fan-out - only directories get the silent treatment.


def test_digest_multipath_directory_is_silently_skipped(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Multi-path fan-out: a directory positional is silently skipped - no
    stderr noise, no error tally, sibling files still render."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    a_dir = tmp_path / "subdir"
    a_dir.mkdir()

    rc = cli._main(["digest", str(conn), str(a_dir)])

    captured = capsys.readouterr()
    assert rc == 0  # ≥1 rendered
    assert len(calls) == 1  # only the conn file routed
    # No directory noise on stderr - that's the point.
    assert "must be a file, not a directory" not in captured.err
    assert str(a_dir) not in captured.err


def test_digest_multipath_all_directories_exits_zero_silently(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Multi-path fan-out where every positional is a directory: no output to
    stdout or stderr, exit 0 (consistent with 'silent skip directories').

    rendered=0, errored=0 → exit-code policy returns 0 via the
    ``errored == 0`` branch in cli.py.
    """
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    d1 = tmp_path / "a"; d1.mkdir()
    d2 = tmp_path / "b"; d2.mkdir()
    d3 = tmp_path / "c"; d3.mkdir()

    rc = cli._main(["digest", str(d1), str(d2), str(d3)])

    captured = capsys.readouterr()
    assert rc == 0
    assert calls == []
    assert captured.out == ""
    assert captured.err == ""


def test_digest_lone_directory_positional_still_errors(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Single positional that is a directory: v1 contract preserved -
    actionable stderr message and exit 1. Whole-directory positionals are
    not supported in v1."""
    _stub_config(monkeypatch)
    _spy_run_digest_calls(monkeypatch)

    a_dir = tmp_path / "logs"
    a_dir.mkdir()

    rc = cli._main(["digest", str(a_dir)])

    captured = capsys.readouterr()
    assert rc == 1
    assert "is a directory - digest takes a file" in captured.err
    assert str(a_dir) in captured.err


def test_digest_multipath_non_directory_errors_still_surface(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Silent-skip applies ONLY to directories - a missing-path positional in
    fan-out still produces its stderr message and tallies as an error."""
    _stub_config(monkeypatch)
    _spy_run_digest_calls(monkeypatch)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(conn), "/no/such/file.log"])

    captured = capsys.readouterr()
    assert rc == 0  # ≥1 rendered (conn)
    assert "not found" in captured.err


# ─── Real-route regression: notice-shape pathless NDJSON → blob ─────────────
#
# A notice.log-shaped pathless Zeek NDJSON (id.orig_h plus native src) must NOT
# reach the conn summariser via the field-set fallback (it crashes with the
# Grouper-not-1-dimensional pandas error): the collision guard rejects the false
# claim at sniff, the orchestrator drops to the blob floor, and the real
# summariser is never invoked - so the defence-in-depth net never fires either.
# Unmocked end-to-end: this test fails if a future change accidentally
# bypasses the guard, even if the recognizer unit tests still pass.


def test_digest_notice_no_path_routes_to_blob_with_no_breadcrumb(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    _stub_config(monkeypatch)

    notice = tmp_path / "notice.log"
    notice.write_text(
        '{"ts": 1779750000.0, "uid": "Cxxxxxx",'
        ' "id.orig_h": "192.0.2.10", "id.orig_p": 41514,'
        ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
        ' "src": "192.0.2.10", "dst": "198.51.100.20",'
        ' "note": "Placeholder::Note", "msg": "placeholder message"}\n',
        encoding="utf-8",
    )

    rc = cli._main(["digest", str(notice)])

    captured = capsys.readouterr()
    assert rc == 0
    # Blob card rendered to stdout - flat-grammar headline + identity line
    # carries the source name.
    assert "Unrecognized source" in captured.out
    assert "notice.log" in captured.out
    # Stderr silent on the defence-in-depth path - the guard prevents the
    # summariser from ever being called, so there is no breadcrumb, no
    # raw pandas error text, no traceback.
    assert "summariser failed" not in captured.err
    assert "Grouper for 'src'" not in captured.err
    assert "ValueError" not in captured.err
    assert "Traceback" not in captured.err


# ─── Blob fallback on summariser raise (item 2) ─────────────────────────────
#
# Defence-in-depth for a recognised-schema summariser raising on a pathological
# frame (e.g. duplicate `src` column → pandas Grouper failure). The narrow
# try/except in run_digest catches Exception (NOT BaseException), is silent on
# stderr by default and emits a one-line breadcrumb under --verbose, and
# always falls back to a blob card for THE SAME file on THE SAME stream.
# Sibling fan-out iterations continue to render.


def test_digest_summariser_failure_falls_back_to_blob(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """A summariser that raises on a recognised conn file produces a blob
    card on the supplied stream. Default mode is SILENT on stderr - the
    breadcrumb is verbose-gated so raw exception text never leaks to the
    operator. No traceback, no abort.

    Coverage strategy: monkeypatch ``sigwood.digest.get_summarizer`` to
    return a callable that raises a synthetic exception. This exercises
    the narrow wrap without contorting a physical fixture into a duplicate-
    column / pathological-schema state - same coverage, smaller blast
    radius."""
    _stub_config(monkeypatch)

    # A real conn NDJSON file - sniff routes to conn, loader succeeds, and
    # the summariser is the only thing that fails.
    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    def _exploding_summarizer(_schema_name: str):
        def _raise(*_a, **_kw):
            raise RuntimeError("induced summariser failure")
        return _raise

    monkeypatch.setattr(
        "sigwood.digest.get_summarizer", _exploding_summarizer,
    )

    rc = cli._main(["digest", str(conn)])

    captured = capsys.readouterr()
    assert rc == 0  # blob card counted as a render
    # Default mode: NO breadcrumb, no raw exception text on stderr.
    assert "summariser failed" not in captured.err
    assert "RuntimeError: induced summariser failure" not in captured.err
    # No traceback in either mode - the rail forbids raw exceptions
    # reaching the user.
    assert "Traceback" not in captured.err
    # Blob card rendered to stdout: flat-grammar headline + identity line.
    assert "Unrecognized source" in captured.out
    assert "conn.log" in captured.out  # identity line carries the source name


def test_digest_summariser_failure_breadcrumb_shown_under_verbose(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Same defence-in-depth path as above, but invoked with --verbose:
    the breadcrumb IS visible on stderr (debug aid). Blob card still
    renders; no traceback in either mode."""
    _stub_config(monkeypatch)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    def _exploding_summarizer(_schema_name: str):
        def _raise(*_a, **_kw):
            raise RuntimeError("induced summariser failure")
        return _raise

    monkeypatch.setattr(
        "sigwood.digest.get_summarizer", _exploding_summarizer,
    )

    rc = cli._main(["digest", "--verbose", str(conn)])

    captured = capsys.readouterr()
    assert rc == 0
    # Verbose: the existing defence-in-depth breadcrumb is visible.
    assert "summariser failed" in captured.err
    assert "RuntimeError: induced summariser failure" in captured.err
    assert "conn.log" in captured.err
    # Still no traceback - verbose adds the breadcrumb, not a stack.
    assert "Traceback" not in captured.err
    # Blob card still renders.
    assert "Unrecognized source" in captured.out
    assert "conn.log" in captured.out


def test_digest_summariser_failure_does_not_abort_sibling_paths(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """In a multi-positional fan-out, a summariser raise on one path falls
    back to a blob card AND lets subsequent paths render their cards.
    Tests that the narrow wrap + blob fallback is a per-path concern, not
    a fan-out abort."""
    _stub_config(monkeypatch)

    # Two real files, both routed to the conn schema by sniff.
    a = tmp_path / "a.log"
    a.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    b = tmp_path / "b.log"
    b.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    # The summariser raises on the FIRST run only - second call succeeds.
    # We monkeypatch get_summarizer to wrap the real one with a one-shot
    # raise so we exercise the actual schema summariser thereafter.
    from sigwood import digest as _digest_pkg
    real_get = _digest_pkg.get_summarizer
    call_n = {"n": 0}

    def _flaky_get(schema_name: str):
        def _wrap(*a, **kw):
            call_n["n"] += 1
            if call_n["n"] == 1:
                raise RuntimeError("induced summariser failure")
            return real_get(schema_name)(*a, **kw)
        return _wrap

    monkeypatch.setattr(
        "sigwood.digest.get_summarizer", _flaky_get,
    )

    rc = cli._main(["digest", str(a), str(b)])

    captured = capsys.readouterr()
    assert rc == 0
    # First file falls back silently (breadcrumb is verbose-gated) - no
    # raw exception text on stderr in default mode.
    assert "summariser failed" not in captured.err
    assert "Traceback" not in captured.err
    # Second file: a real conn card renders (identity line carries "conn ·").
    assert "conn ·" in captured.out
    # First file rendered a blob card as well - its headline is present.
    assert "Unrecognized source" in captured.out


def test_digest_runner_value_error_does_not_abort_loop(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """A ValueError raised inside run_digest for one path is caught and
    tallied; subsequent valid paths still render."""
    _stub_config(monkeypatch)

    calls: list[Path] = []

    def flaky_run_digest(**kwargs):
        # First call (conn) raises; second call (dns) succeeds.
        called_for = kwargs.get("zeek_dir")
        calls.append(called_for)
        if len(calls) == 1:
            raise ValueError("induced parser failure")

    monkeypatch.setattr(runner, "run_digest", flaky_run_digest)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    dns = tmp_path / "dns.log"
    dns.write_text(_ZEEK_DNS_NDJSON_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(conn), str(dns)])

    captured = capsys.readouterr()
    assert rc == 0  # ≥1 rendered (the dns path)
    assert len(calls) == 2
    assert "induced parser failure" in captured.err


# ─── Shared --out concatenation ──────────────────────────────────────────────


def test_digest_out_directory_writes_single_named_file(
    tmp_path: Path, monkeypatch,
) -> None:
    """N valid paths with --out=<dir>/ → exactly one sigwood-digest_<first>_<date>.txt
    in the directory (token = FIRST positional's basename), populated by all
    run_digest streams in argv order."""
    _stub_config(monkeypatch)
    date = datetime.now().strftime("%Y%m%d")

    streams_received: list[Any] = []

    def fake_run_digest(**kwargs):
        # Simulate render: write a schema tag to the provided stream.
        stream = kwargs.get("stream")
        streams_received.append(stream)
        stream.write(f"[card {kwargs['schema']}]\n")

    monkeypatch.setattr(runner, "run_digest", fake_run_digest)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    syslog = tmp_path / "sl.log"
    syslog.write_text(_SYSLOG_LINE, encoding="utf-8")
    out_dir = tmp_path / "out"

    rc = cli._main(["digest", str(conn), str(syslog), f"--out={out_dir}/"])

    assert rc == 0
    files = sorted(out_dir.iterdir())
    assert len(files) == 1
    # Token = FIRST positional's basename only; the second never contributes.
    assert files[0].name == f"sigwood-digest_conn_{date}.txt"
    assert "sl" not in files[0].name
    # Both calls wrote into the same TextIO.
    assert streams_received[0] is streams_received[1]
    body = files[0].read_text(encoding="utf-8")
    assert body == "[card conn]\n[card syslog]\n"


def test_digest_out_explicit_file_honors_path(
    tmp_path: Path, monkeypatch,
) -> None:
    """`--out=<explicit-file>` with N paths → that exact file, all cards."""
    _stub_config(monkeypatch)

    def fake_run_digest(**kwargs):
        kwargs["stream"].write(f"[card {kwargs['schema']}]\n")

    monkeypatch.setattr(runner, "run_digest", fake_run_digest)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    dns = tmp_path / "dns.log"
    dns.write_text(_ZEEK_DNS_NDJSON_LINE, encoding="utf-8")
    explicit = tmp_path / "my_report.txt"

    rc = cli._main(["digest", str(conn), str(dns), f"--out={explicit}"])

    assert rc == 0
    assert explicit.read_text(encoding="utf-8") == "[card conn]\n[card dns]\n"


def test_digest_out_directory_real_render_saves_default_window_note(
    tmp_path: Path, monkeypatch,
) -> None:
    """Real CLI path (run_digest NOT stubbed): a bare-config Zeek DIRECTORY
    digest with --out resolves a default window, renders the card to a file,
    and the DURABLE saved digest contains the default-window disclosure note.
    Proves the note travels into the saved file, not just stdout."""
    cfg_zeek = tmp_path / "zeek"
    cfg_zeek.mkdir()
    base = datetime(2026, 6, 11, 12, 0, tzinfo=timezone.utc).timestamp()
    body_in = "".join(
        f'{{"ts": {base - i * 3600}, "id.orig_h": "192.0.2.10",'
        f' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",'
        f' "duration": 1.0}}\n'
        for i in range(6)
    )
    (cfg_zeek / "conn.log").write_text(body_in, encoding="utf-8")

    out_dir = tmp_path / "report"
    date = datetime.now().strftime("%Y%m%d")
    _stub_config(monkeypatch, {"sigwood": {
        "zeek_dir": str(cfg_zeek), "default_window": "1d",
    }})

    rc = cli._main(["digest", f"--out={out_dir}/"])

    assert rc == 0
    out_file = out_dir / f"sigwood-digest_{date}.txt"  # bare → no token
    body = out_file.read_text(encoding="utf-8")
    assert default_window_advisory("1d") in body


def test_digest_single_positional_with_out_directory_uses_same_naming(
    tmp_path: Path, monkeypatch,
) -> None:
    """N=1 with `--out=<dir>/` uses sigwood-digest_<first>_<date>.txt - no special case
    (fan-out and bare share the one scheme)."""
    _stub_config(monkeypatch)
    date = datetime.now().strftime("%Y%m%d")
    monkeypatch.setattr(
        runner, "run_digest",
        lambda **kw: kw["stream"].write(f"[card {kw['schema']}]\n"),
    )

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    out_dir = tmp_path / "out"

    rc = cli._main(["digest", str(conn), f"--out={out_dir}/"])

    assert rc == 0
    files = sorted(out_dir.iterdir())
    assert len(files) == 1 and files[0].name == f"sigwood-digest_conn_{date}.txt"
    assert files[0].read_text(encoding="utf-8") == "[card conn]\n"


# ─── Lazy stream - no file created when nothing renders ─────────────────────


def test_digest_out_directory_with_all_empty_creates_no_file(
    tmp_path: Path, monkeypatch,
) -> None:
    """All-empty fan-out with --out=<dir>/ → no file is created (lazy open
    proof)."""
    _stub_config(monkeypatch)
    _spy_run_digest_calls(monkeypatch)

    a = tmp_path / "a.log"
    a.write_text("", encoding="utf-8")
    b = tmp_path / "b.log"
    b.write_text("", encoding="utf-8")
    out_dir = tmp_path / "out"

    rc = cli._main(["digest", str(a), str(b), f"--out={out_dir}/"])

    assert rc == 0
    assert not out_dir.exists() or list(out_dir.iterdir()) == []


def test_digest_out_directory_with_all_error_creates_no_file(
    tmp_path: Path, monkeypatch,
) -> None:
    """All-error fan-out with --out=<dir>/ → no file is created and exit 1."""
    _stub_config(monkeypatch)
    _spy_run_digest_calls(monkeypatch)

    out_dir = tmp_path / "out"

    rc = cli._main(["digest", "/no/such.log", "/also/missing.log", f"--out={out_dir}/"])

    assert rc == 1
    assert not out_dir.exists() or list(out_dir.iterdir()) == []


# ─── Dry-run sidesteps --out ────────────────────────────────────────────────


def test_digest_dry_run_with_out_creates_no_file(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """`digest *.log --dry-run --out=<dir>/` → no file materialises."""
    _stub_config(monkeypatch)

    # run_digest's dry-run branch must NOT receive an opened file stream.
    # We let the real runner.run_digest run with dry_run=True so its early
    # return is exercised, but spy on what stream= it was handed.
    seen_streams: list[Any] = []

    def fake_run_digest(**kwargs):
        seen_streams.append(kwargs.get("stream"))
        # dry-run never opens the handler in real runner.run_digest; mimic.

    monkeypatch.setattr(runner, "run_digest", fake_run_digest)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    out_dir = tmp_path / "out"

    rc = cli._main(["digest", str(conn), "--dry-run", f"--out={out_dir}/"])

    assert rc == 0
    # Dry-run → get_stream() returned sys.stdout (or None per design); MUST
    # not have opened a file in out_dir.
    assert not out_dir.exists() or list(out_dir.iterdir()) == []
    # Stream handed in is stdout (dry-run helper returns sys.stdout); never a
    # file we opened.
    assert seen_streams[0] is sys.stdout


# ─── Bare ``digest`` (no positional) still uses config-driven flow ──────────


def test_digest_bare_no_positional_resolves_output_via_kwargs(
    tmp_path: Path, monkeypatch,
) -> None:
    """Bare ``digest`` (no positional) is the config-driven path - output is
    resolved by _digest_runner_kwargs via the out-only resolver. A DIR verdict is
    COMPOSED into an exact output_file (no token - no positional); output_dir is
    always None for digest so the runner never reaches _report_filename."""
    cfg_zeek = tmp_path / "zeek"
    cfg_zeek.mkdir()
    out_dir = tmp_path / "report"
    date = datetime.now().strftime("%Y%m%d")
    _stub_config(monkeypatch, {"sigwood": {"zeek_dir": str(cfg_zeek)}})

    captured: dict[str, Any] = {}
    monkeypatch.setattr(runner, "run_digest", lambda **kw: captured.update(kw))

    rc = cli._main(["digest", f"--out={out_dir}/"])
    assert rc == 0
    # DIR verdict composed into an exact file; output_dir never threaded.
    assert captured.get("output_dir") is None
    out_file = captured.get("output_file")
    assert out_file is not None
    assert out_file == out_dir / f"sigwood-digest_{date}.txt"  # bare → no token
    assert captured.get("stream") is None  # CLI never threads a stream here
    assert captured.get("schema") == "conn"


# ─── Digest is OFF report_dir; -o=- forces stdout; path narration ───────────


def test_digest_dash_out_forces_stdout(tmp_path: Path, monkeypatch, capsys) -> None:
    """`--out=-` forces stdout (no file), and narrates no write."""
    _stub_config(monkeypatch)
    streams: list[Any] = []
    monkeypatch.setattr(
        runner, "run_digest",
        lambda **kw: (streams.append(kw["stream"]), kw["stream"].write("x\n")),
    )
    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(conn), "--out=-"])

    assert rc == 0
    assert streams[0] is sys.stdout
    assert "wrote digest" not in capsys.readouterr().err


def test_digest_fanout_ignores_report_dir_writes_stdout(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """report_dir set + no --out → digest goes to STDOUT, report_dir untouched."""
    rd = tmp_path / "reports"
    rd.mkdir()
    _stub_config(monkeypatch, {"sigwood": {"report_dir": str(rd)}})
    streams: list[Any] = []
    monkeypatch.setattr(
        runner, "run_digest",
        lambda **kw: (streams.append(kw["stream"]), kw["stream"].write("x\n")),
    )
    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(conn)])

    assert rc == 0
    assert streams[0] is sys.stdout
    assert list(rd.iterdir()) == []  # report_dir never touched by digest
    assert "wrote digest" not in capsys.readouterr().err


def test_digest_fanout_narrates_written_file(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """A fan-out file write → one `wrote digest to <path>` stderr line."""
    _stub_config(monkeypatch)
    date = datetime.now().strftime("%Y%m%d")
    monkeypatch.setattr(runner, "run_digest", lambda **kw: kw["stream"].write("x\n"))
    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    out_dir = tmp_path / "out"

    rc = cli._main(["digest", str(conn), f"--out={out_dir}/"])

    assert rc == 0
    err = capsys.readouterr().err
    assert "wrote digest to" in err
    assert f"sigwood-digest_conn_{date}.txt" in err


def test_digest_fanout_quiet_suppresses_narration(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    _stub_config(monkeypatch)
    monkeypatch.setattr(runner, "run_digest", lambda **kw: kw["stream"].write("x\n"))
    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    out_dir = tmp_path / "out"

    rc = cli._main(["digest", str(conn), f"--out={out_dir}/", "-q"])

    assert rc == 0
    assert "wrote digest" not in capsys.readouterr().err


def test_digest_bare_narrates_written_file(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Bare digest with --out=file → `wrote digest to <path>` after a clean run."""
    cfg_zeek = tmp_path / "zeek"
    cfg_zeek.mkdir()
    _stub_config(monkeypatch, {"sigwood": {"zeek_dir": str(cfg_zeek)}})
    monkeypatch.setattr(runner, "run_digest", lambda **kw: None)  # clean return
    target = tmp_path / "card.txt"

    rc = cli._main(["digest", f"--out={target}"])

    assert rc == 0
    assert f"wrote digest to {target}" in capsys.readouterr().err


def test_digest_fanout_narration_strips_control_bytes(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """A control byte in the fan-out --out directory must not reach the
    `wrote digest to <path>` completion line raw (--out is operator/config input
    and the line is intended for a terminal or log)."""
    _stub_config(monkeypatch)
    monkeypatch.setattr(runner, "run_digest", lambda **kw: kw["stream"].write("x\n"))
    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    out_dir = tmp_path / f"out{chr(0x1b)}zone"

    rc = cli._main(["digest", str(conn), f"--out={out_dir}/"])

    assert rc == 0
    err = capsys.readouterr().err
    assert "wrote digest to" in err          # the narration rendered
    assert "outzone" in err                  # the (stripped) directory name
    assert chr(0x1b) not in err


def test_digest_bare_narration_strips_control_bytes(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """A control byte in the bare-config --out file must not reach the
    `wrote digest to <path>` completion line raw."""
    cfg_zeek = tmp_path / "zeek"
    cfg_zeek.mkdir()
    _stub_config(monkeypatch, {"sigwood": {"zeek_dir": str(cfg_zeek)}})
    monkeypatch.setattr(runner, "run_digest", lambda **kw: None)  # clean return
    target = tmp_path / f"card{chr(0x1b)}zone.txt"

    rc = cli._main(["digest", f"--out={target}"])

    assert rc == 0
    err = capsys.readouterr().err
    assert "cardzone.txt" in err             # the (stripped) file name
    assert chr(0x1b) not in err


# ─── Detect-path regression: parsed["paths"] does not bleed into detector ──


def test_detect_path_unaffected_by_new_paths_key(
    tmp_path: Path, monkeypatch,
) -> None:
    """A detector invocation with a positional still routes through
    parsed["path"] only; the new parsed["paths"] key is irrelevant."""
    _stub_config(monkeypatch)

    captured: dict[str, Any] = {}
    monkeypatch.setattr(runner, "run", lambda **kwargs: captured.update(kwargs))

    log_path = tmp_path / "conn.log"
    log_path.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    cli._main(["beacon", str(log_path)])

    # Detector routes the positional to its required source key (zeek_dir).
    assert captured.get("zeek_dir") == str(log_path)
    assert captured.get("detect") == "beacon"


# ─── Source-dir flags rejected in fan-out ──────────────────────────────────


def test_digest_source_dir_flag_rejected_with_positional(
    tmp_path: Path, monkeypatch,
) -> None:
    """Source-dir flags are meaningless in fan-out - rejected up front.

    --zeek-dir remains an advertised digest flag (useful for bare
    config-driven conn digest), so with a positional present it hits the
    positional-guard 'not valid alongside' error. The other three
    (--pihole-dir, --syslog-dir, --cloudtrail-dir) are not in the digest
    allowed set under the spec-driven parser, and raise the spec's
    wrong-verb error ('is not valid for digest'). Either way the
    combination is rejected."""
    _stub_config(monkeypatch)
    log_path = tmp_path / "conn.log"
    log_path.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    with pytest.raises(ValueError, match="--zeek-dir is not valid alongside"):
        cli._main(["digest", str(log_path), "--zeek-dir=/x"])
    for pruned in ("--pihole-dir", "--syslog-dir", "--cloudtrail-dir"):
        with pytest.raises(ValueError, match=f"{pruned} is not valid for digest"):
            cli._main(["digest", str(log_path), f"{pruned}=/x"])


def test_digest_unrecognized_single_file_still_routes_to_blob(
    tmp_path: Path, monkeypatch,
) -> None:
    """The blob route lives at the CLI sniff layer, NOT inside run_digest.
    A single-file Zeek bypass in run_digest must not introduce a new path
    around that floor: unrecognized / garbage content must still sniff to
    ``schema="blob"`` and reach run_digest via ``blob_path``."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)
    garbage = tmp_path / "garbage.dat"
    garbage.write_text(_BLOB_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(garbage)])

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["schema"] == "blob"
    assert calls[0]["blob_path"] == garbage


def test_digest_pruned_source_dir_flags_rejected_without_positional(
    monkeypatch,
) -> None:
    """Without a positional, the pruned source-dir flags should also fail
    with the spec-driven wrong-verb error - these flags are not in digest's
    allowed set (schema is always conn with no positional, so only
    --zeek-dir is meaningful). Locks the allowed-set asymmetry."""
    _stub_config(monkeypatch)
    for pruned in ("--pihole-dir", "--syslog-dir", "--cloudtrail-dir"):
        with pytest.raises(ValueError, match=f"{pruned} is not valid for digest"):
            cli._main(["digest", f"{pruned}=/x"])


# ─── Zeek syslog.log v1 promotion - fan-out routing + kwargs xor ladder ─────

_ZEEK_NDJSON_SYSLOG_LINE = (
    '{"_path":"syslog","ts":1779750000.0,"uid":"CSL01",'
    '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20","id.resp_p":514,'
    '"proto":"udp","facility":"DAEMON","severity":"INFO",'
    '"message":"Jun 11 12:00:00 host1 sshd[1234]: ok"}\n'
)


def test_digest_zeek_syslog_positional_routes_to_zeek_dir(
    tmp_path: Path, monkeypatch,
) -> None:
    """A sniffed Zeek `syslog.log` positional (origin "zeek") synthesises
    zeek_dir via _route_sniffed_path's new syslog origin split - mirrors the
    dns origin split for Zeek vs Pi-hole."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    zeek_syslog = tmp_path / "syslog.log"
    zeek_syslog.write_text(_ZEEK_NDJSON_SYSLOG_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(zeek_syslog)])

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["schema"] == "syslog"
    assert calls[0]["zeek_dir"] == str(zeek_syslog)
    assert calls[0]["syslog_dir"] is None


def test_digest_flat_syslog_positional_still_routes_to_syslog_dir(
    tmp_path: Path, monkeypatch,
) -> None:
    """Flat rsyslog (origin "syslog") continues to synthesise syslog_dir -
    the origin split must not regress the historical path."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    flat = tmp_path / "syslog"
    flat.write_text(_SYSLOG_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(flat)])

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["schema"] == "syslog"
    assert calls[0]["syslog_dir"] == str(flat)
    assert calls[0]["zeek_dir"] is None


# ``_digest_runner_kwargs`` does NOT resolve source dirs - it passes raw
# strings (or None) to ``run_digest``, which calls
# ``common.sources.resolve_digest_source``. The ladder + XOR +
# config-preference logic lives there:
#
#   syslog_dir > zeek_dir fallback     → tests/test_sources.py:
#                                          test_digest_syslog_syslog_preference_on_config_fallback
#                                          test_digest_syslog_zeek_when_only_zeek_configured
#   syslog XOR (zeek_dir + syslog_dir) → tests/test_sources.py:
#                                          test_digest_syslog_xor_byte_preserved


def test_digest_zeek_syslog_without_path_renders_syslog_card(
    tmp_path: Path, monkeypatch,
) -> None:
    """A Zeek-NDJSON syslog.log without `_path` must sniff to
    `schema="syslog", origin="zeek"` and route to zeek_dir, NOT fall into the
    conn fallback. It must not render a conn card (or crash) instead of the
    syslog card."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    no_path = tmp_path / "syslog.log"
    no_path.write_text(
        '{"ts":1779750000.0,"uid":"CSL01",'
        '"id.orig_h":"192.0.2.10","id.orig_p":41514,'
        '"id.resp_h":"198.51.100.20","id.resp_p":514,'
        '"proto":"udp","facility":"DAEMON","severity":"INFO",'
        '"message":"Jun 11 12:00:00 host1 sshd[1234]: placeholder"}\n',
        encoding="utf-8",
    )

    rc = cli._main(["digest", str(no_path)])

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["schema"] == "syslog"
    assert calls[0]["zeek_dir"] == str(no_path)
    assert calls[0]["syslog_dir"] is None


# ─── Inter-card separator matrix ────────────────────────────────────────────
#
# A 40-col "─" * 40 rule separates adjacent RENDERED cards on a multi-card
# run; single-card runs draw no rule at all. Render-commit placement:
# `run_digest` / `_render_blob_for_path` emit the rule immediately before
# `handler.render_*(card)`, so a separator only ever precedes a card that
# reaches its render call. Skipped/empty/errored paths never trigger a rule.

_INTER_CARD_RULE = "─" * 40
_ZEEK_NDJSON_DNS_LINE = (
    '{"_path": "dns", "ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 53, "proto": "udp",'
    ' "query": "example.test", "qtype": 1, "rcode": 0}\n'
)


def test_inter_card_separator_single_card_run_draws_no_rule(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """One positional → one card → no separator anywhere."""
    _stub_config(monkeypatch)
    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(conn)])

    captured = capsys.readouterr()
    assert rc == 0
    assert _INTER_CARD_RULE not in captured.out


def test_inter_card_separator_two_schema_cards_get_one_rule_between(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Two rendered schema cards → exactly one rule between, none before
    the first or after the last."""
    _stub_config(monkeypatch)
    a = tmp_path / "a.log"
    a.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    b = tmp_path / "b.log"
    b.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(a), str(b)])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out.count(_INTER_CARD_RULE) == 1
    # The first emitted line is identity-line-1 of card 1 (no leading rule).
    assert captured.out.splitlines()[0] == "a.log"
    # Output does not end with a trailing rule.
    assert not captured.out.rstrip("\n").endswith(_INTER_CARD_RULE)


def test_inter_card_separator_skipped_path_does_not_get_rule(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """An empty positional sitting BETWEEN two valid paths produces
    exactly one rule, placed correctly (not adjacent to the empty path)."""
    _stub_config(monkeypatch)
    a = tmp_path / "a.log"
    a.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    b = tmp_path / "b.log"
    b.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(a), str(empty), str(b)])

    captured = capsys.readouterr()
    assert rc == 0
    # One rule total - between the two rendered cards. The empty path
    # was skipped before any render-commit, so no separator fired for it.
    assert captured.out.count(_INTER_CARD_RULE) == 1


def test_inter_card_separator_schema_to_blob_top_level(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Schema card followed by a top-level blob (sniff floor) → one rule."""
    _stub_config(monkeypatch)
    conn = tmp_path / "a.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    unknown = tmp_path / "mystery.txt"
    unknown.write_text("alpha beta gamma\ndelta epsilon\n" * 50, encoding="utf-8")

    rc = cli._main(["digest", str(conn), str(unknown)])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out.count(_INTER_CARD_RULE) == 1


def test_inter_card_separator_schema_to_internal_blob_fallback(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """Schema card followed by a summariser-failure blob fallback → exactly
    one rule (single owner: _render_blob_for_path emits, run_digest does
    not double-emit on the fallback arm)."""
    _stub_config(monkeypatch)
    a = tmp_path / "a.log"
    a.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    b = tmp_path / "b.log"
    b.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    # Flake the SECOND summariser call so the first card renders normally
    # and the second falls back to a blob.
    from sigwood import digest as _digest_pkg
    real_get = _digest_pkg.get_summarizer
    call_n = {"n": 0}

    def _flaky_get(schema_name: str):
        def _wrap(*a, **kw):
            call_n["n"] += 1
            if call_n["n"] == 2:
                raise RuntimeError("induced summariser failure")
            return real_get(schema_name)(*a, **kw)
        return _wrap

    monkeypatch.setattr("sigwood.digest.get_summarizer", _flaky_get)

    rc = cli._main(["digest", str(a), str(b)])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out.count(_INTER_CARD_RULE) == 1


# ─── Loader-progress suppression on multi-file fan-out ──────────────────────


def test_digest_single_positional_keeps_loader_progress(
    tmp_path: Path, monkeypatch,
) -> None:
    """A single-positional digest still wants the loader bar - nothing
    renders below it to pollute, and a large log is exactly when feedback
    matters. run_digest must receive show_progress=True."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(conn)])

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["show_progress"] is True


def test_digest_multi_positional_suppresses_loader_progress(
    tmp_path: Path, monkeypatch,
) -> None:
    """Multi-positional fan-out: every card receives show_progress=False so
    the loader's leave=True bar can't interleave between a rendered card and
    the next card's separator. Suppress batch-wide (not just subsequent
    cards) - in a batch the cards are the whole report."""
    _stub_config(monkeypatch)
    calls = _spy_run_digest_calls(monkeypatch)

    a = tmp_path / "a.log"
    a.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    b = tmp_path / "b.log"
    b.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    rc = cli._main(["digest", str(a), str(b)])

    assert rc == 0
    assert len(calls) == 2
    assert all(c["show_progress"] is False for c in calls)


def test_inter_card_separator_out_concatenation_matches_stdout_fanout(
    tmp_path: Path, monkeypatch,
) -> None:
    """`--out` concatenation produces the same separator behavior as the
    stdout fan-out - one rule between two rendered cards, none at edges."""
    _stub_config(monkeypatch)
    a = tmp_path / "a.log"
    a.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    b = tmp_path / "b.log"
    b.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    out = tmp_path / "digest.txt"

    rc = cli._main(["digest", str(a), str(b), f"--out={out}"])

    assert rc == 0
    content = out.read_text(encoding="utf-8")
    assert content.count(_INTER_CARD_RULE) == 1
    assert not content.rstrip("\n").endswith(_INTER_CARD_RULE)


# ── --utc / use_utc: the CLI-side auto-name date follows the knob ─────────────


def test_digest_out_dir_filename_date_follows_the_knob(
    tmp_path: Path, monkeypatch, pin_tz, restore_display_utc,
) -> None:
    """A digest DIRECTORY --out auto-name date follows the display setting from
    EITHER knob source (--utc flag; config use_utc), and stays local with
    neither - the regression for CLI-side naming-before-run ordering (the
    switch must be set before _resolve_digest_output_target, not at run_digest
    entry). A ±12h zone is pinned at runtime so the local and UTC dates DIFFER
    right now; expected dates come from the display seam with the switch set
    in-test and RESET before each CLI call (the CLI must set it itself)."""
    from datetime import timezone as _tz

    from sigwood.common.display import set_display_utc, to_display_timezone

    if datetime.now(_tz.utc).hour < 12:
        pin_tz("Etc/GMT+12")   # POSIX sign inversion: UTC-12 → local date behind UTC
    else:
        pin_tz("Etc/GMT-12")   # UTC+12 → local date ahead of UTC

    def expected_date(state: bool) -> str:
        set_display_utc(state)
        try:
            return to_display_timezone(datetime.now(_tz.utc)).strftime("%Y%m%d")
        finally:
            set_display_utc(False)

    def digest_to(out_dir: Path, extra: list[str], cfg_dict: dict) -> str:
        _stub_config(monkeypatch, cfg_dict)
        monkeypatch.setattr(
            runner, "run_digest",
            lambda **kwargs: kwargs["stream"].write("[card]\n"),
        )
        conn = tmp_path / "conn.log"
        conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
        rc = cli._main(["digest", str(conn), f"--out={out_dir}/", *extra])
        assert rc == 0
        files = sorted(out_dir.iterdir())
        assert len(files) == 1
        return files[0].name

    def assert_named_for(state: bool, name: str, before: str) -> None:
        # Expected date computed BEFORE and AFTER the run - a midnight
        # rollover between the CLI's clock read and this check cannot flake.
        after = expected_date(state)
        assert name in {f"sigwood-digest_conn_{d}.txt" for d in (before, after)}

    # --utc flag → UTC date.
    before = expected_date(True)
    name = digest_to(tmp_path / "o1", ["--utc"], {"sigwood": {}})
    assert_named_for(True, name, before)
    set_display_utc(False)  # the CLI set the process global; reset between cases

    # config use_utc = true → UTC date.
    before = expected_date(True)
    name = digest_to(tmp_path / "o2", [], {"sigwood": {"use_utc": True}})
    assert_named_for(True, name, before)
    set_display_utc(False)

    # Neither → local date, which the pinned zone makes DIFFERENT from UTC's.
    before = expected_date(False)
    name = digest_to(tmp_path / "o3", [], {"sigwood": {}})
    assert_named_for(False, name, before)
    assert expected_date(False) != expected_date(True)
