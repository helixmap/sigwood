"""Control bytes in attacker-influenced names must not reach an output sink raw.

A filename, directory name, S3 object key, exception message, or config-value
path can carry a terminal control byte (here an ESC, U+001B). If it reaches
stdout/stderr un-neutralized, a `cat`'d log or a live terminal can be made to
forge or hide output. Each probe drives a real public seam (the CLI dispatcher,
the loader API, or the exporter orchestrator), asserts the ESC never survives to
the stream, and checks the sink actually rendered (a non-ESC marker survives) so
a pass is never vacuous.

ESC is built with ``chr(0x1b)`` - the source carries no control byte, and a real
ESC exists only at runtime. Config values are injected programmatically (a
literal ESC in a TOML basic string fails ``tomllib``); filenames carry a real ESC
created programmatically.
"""

from __future__ import annotations

import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sigwood.cli as cli
from sigwood.common import loader
from sigwood import exporters
from sigwood.exporters import cloudtrail as ct

ESC = chr(0x1B)
# An ESC split between two markers; stripping rejoins them, so the stripped form
# proves the sink rendered the value.
_STRIPPED = "escprobezone"


def _esc(prefix: str = "escprobe", suffix: str = "zone", ext: str = "") -> str:
    return f"{prefix}{ESC}{suffix}{ext}"


_TSV_CONN_HEADER = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
    "\tproto\tservice\tduration\torig_bytes\tresp_bytes"
    "\tconn_state\tlocal_orig\tlocal_resp\ttunnel_parents\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport"
    "\tenum\tstring\tinterval\tcount\tcount"
    "\tstring\tbool\tbool\tset[string]\n"
)


def _header_only_conn(path: Path) -> None:
    """A Zeek conn TSV with a complete #path conn header but zero data rows:
    recognized-but-empty, so run_digest raises DigestEmpty."""
    path.write_text(
        _TSV_CONN_HEADER + "#close\t2026-01-01-00:00:00\n", encoding="utf-8"
    )


@pytest.fixture(autouse=True)
def _isolate_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never read the dev box's real ~/.sigwood/config.toml; a probe that needs
    a specific source dir re-monkeypatches cli.cfg.load itself."""
    monkeypatch.setattr(cli.cfg, "load", lambda _p: {"sigwood": {}})


def _set_config(monkeypatch: pytest.MonkeyPatch, sigwood: dict) -> None:
    monkeypatch.setattr(cli.cfg, "load", lambda _p: {"sigwood": sigwood})


# ── cli.py error boundary ────────────────────────────────────────────────────


def test_unknown_command_strips_control(capsys) -> None:
    # cli.py:266 - argv[0] is echoed verbatim in the unknown-command message.
    with pytest.raises(SystemExit):
        cli._main([_esc()])
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


def test_hunt_missing_positional_strips_control(tmp_path, capsys) -> None:
    # cli.py:219 - the ValueError arm ("{path}: not found") is the proven hole.
    missing = str(tmp_path / _esc(ext=".log"))
    with pytest.raises(SystemExit):
        cli.main(["hunt", missing])
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


# ── cli.py digest fan-out ────────────────────────────────────────────────────


def test_digest_not_found_strips_control(tmp_path, capsys) -> None:
    # cli.py:1171
    cli._main(["digest", str(tmp_path / _esc(ext=".log"))])
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


def test_digest_directory_strips_control(tmp_path, capsys) -> None:
    # cli.py:1181
    d = tmp_path / _esc()
    d.mkdir()
    cli._main(["digest", str(d)])
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


def test_digest_empty_file_strips_control(tmp_path, capsys) -> None:
    # cli.py:1189 - this line is STDOUT.
    f = tmp_path / _esc(ext=".log")
    f.write_text("", encoding="utf-8")
    cli._main(["digest", str(f)])
    out = capsys.readouterr().out
    assert ESC not in out
    assert _STRIPPED in out


def test_digest_recognized_empty_fanout_strips_control(tmp_path, capsys) -> None:
    # cli.py:1209 - fan-out DigestEmpty; basename is the FILE name.
    f = tmp_path / _esc(ext=".conn.log")
    _header_only_conn(f)
    cli._main(["digest", str(f)])
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


def test_digest_recognized_empty_bare_config_strips_control(
    tmp_path, monkeypatch, capsys
) -> None:
    # cli.py:1145 - the BARE-CONFIG DigestEmpty branch (no positional); basename
    # is the configured directory name. Distinct from the fan-out branch (1209).
    zeek_dir = tmp_path / _esc()
    zeek_dir.mkdir()
    _header_only_conn(zeek_dir / "conn.log")
    _set_config(monkeypatch, {"zeek_dir": str(zeek_dir), "default_window": "all"})
    cli._main(["digest"])
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


def test_digest_permission_denied_strips_control(
    tmp_path, monkeypatch, capsys
) -> None:
    # cli.py:1217 - _permission_denied_message(path) embeds path.name. The sniff
    # seam is monkeypatched to raise PermissionError (chmod is platform-sensitive)
    # while the real CLI digest loop runs.
    f = tmp_path / _esc(ext=".log")
    f.write_text("data\n", encoding="utf-8")

    def _raise_perm(path):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(loader, "sniff_format_detailed", _raise_perm)
    cli._main(["digest", str(f)])
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


def test_digest_parse_error_strips_control(tmp_path, monkeypatch, capsys) -> None:
    # cli.py:1224 - the (ValueError, OSError) arm: "{path.name}: {exc}". The sniff
    # seam is monkeypatched to raise ValueError while the real CLI loop runs.
    f = tmp_path / _esc(ext=".log")
    f.write_text("data\n", encoding="utf-8")

    def _raise_value(path):
        raise ValueError("bad content")

    monkeypatch.setattr(loader, "sniff_format_detailed", _raise_value)
    cli._main(["digest", str(f)])
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


# ── runner dry-run STDOUT banner ─────────────────────────────────────────────


def test_hunt_dry_run_family_and_skip_strips_control(monkeypatch, capsys) -> None:
    # runner.py:1095/1096/1098 (source-family block) + 1154 (skip reason). A
    # non-existent ESC zeek_dir appears in the family line AND the skip reason.
    esc_dir = f"/nonexistent/{_esc()}"
    _set_config(
        monkeypatch,
        {
            "zeek_dir": esc_dir,
            "syslog_dir": None,
            "pihole_dir": None,
            "cloudtrail_dir": None,
            "detect": "all",
        },
    )
    cli._main(["hunt", "--dry-run"])
    out = capsys.readouterr().out
    assert ESC not in out
    assert _STRIPPED in out
    assert "skipped" in out  # a skip reason rendered (non-vacuous)


def test_digest_dry_run_blob_path_strips_control(tmp_path, capsys) -> None:
    # runner.py:1962 - digest --dry-run prints an unrecognized (blob) positional.
    blob = tmp_path / _esc(ext=".dat")
    blob.write_text("unrecognizable random content 12345\n", encoding="utf-8")
    cli._main(["digest", "--dry-run", str(blob)])
    out = capsys.readouterr().out
    assert ESC not in out
    assert _STRIPPED in out


def test_digest_dry_run_source_dir_strips_control(
    tmp_path, monkeypatch, capsys
) -> None:
    # runner.py:2038 - bare digest --dry-run prints the configured source dir.
    zeek_dir = tmp_path / _esc()
    zeek_dir.mkdir()
    _header_only_conn(zeek_dir / "conn.log")
    _set_config(monkeypatch, {"zeek_dir": str(zeek_dir), "default_window": "all"})
    cli._main(["digest", "--dry-run"])
    out = capsys.readouterr().out
    assert ESC not in out
    assert _STRIPPED in out


# ── common/loader verbose diagnostics ────────────────────────────────────────


def test_loader_wrong_family_skip_strips_control(tmp_path, capsys) -> None:
    # pipeline.py:635 - the syslog wrong-family skip message embeds path.name.
    # Real loader public seam: an EXPLICIT NDJSON file routed to syslog_dir
    # reaches _syslog_should_skip (a directory-discovered file would be
    # content-gated out before the sink).
    f = tmp_path / _esc(ext=".json")
    f.write_text('{"a": 1}\n{"b": 2}\n', encoding="utf-8")
    loader.load_required_logs(
        {"*.log*": "syslog_dir"}, {"syslog_dir": [f]}, verbose=True
    )
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


def test_loader_rotation_window_skip_strips_control(tmp_path, capsys) -> None:
    # windowing.py:482 - a rotation file skipped as outside the window prints its
    # name under verbose. Real loader public seam (the CLI rotation setup is
    # brittle). Timestamps are now-relative so the recent/old order is stable on
    # any run date (RFC 3164 carries no year).
    d = tmp_path / "rot"
    d.mkdir()
    now = datetime.now(timezone.utc)

    def _rfc3164(dt: datetime) -> str:
        return dt.strftime("%b %d %H:%M:%S") + " examplehost prog: message\n"

    # A 3-file rotation group: the OLDEST file's whole range falls before the
    # window. (A 2-file group's older file reaches up to the newer file's start,
    # so its range still overlaps the window and it is not skipped.)
    (d / _esc(ext=".log")).write_text(_rfc3164(now), encoding="utf-8")
    (d / _esc(ext=".log.1")).write_text(
        _rfc3164(now - timedelta(days=5)), encoding="utf-8"
    )
    (d / _esc(ext=".log.2")).write_text(
        _rfc3164(now - timedelta(days=20)), encoding="utf-8"
    )

    loader.load_required_logs(
        {"*.log*": "syslog_dir"},
        {"syslog_dir": [d]},
        since=now - timedelta(days=3),
        verbose=True,
    )
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err


# ── exporter narration ───────────────────────────────────────────────────────


def test_export_narration_strips_control(tmp_path, monkeypatch, capsys) -> None:
    # The real run_export orchestrator drives a stubbed external fetch. The query
    # and descriptor remain hostile narration values; the output basename is safe
    # because provenance entry keys deliberately reject control-bearing names.
    from sigwood.exporters import splunk as splunk_module

    esc_query = _esc(prefix="q", suffix="name")
    from sigwood.common.paths import private_write_bytes

    monkeypatch.setattr(
        splunk_module, "summary_descriptor", lambda cfg: _esc(prefix="host", suffix="desc")
    )
    monkeypatch.setattr(
        splunk_module, "fetch",
        lambda *a, **kw: ([], {"units": 0, "unit_label": "chunks"}),
    )
    monkeypatch.setattr(
        splunk_module, "write",
        lambda rows, outpath, verbose: (
            private_write_bytes(outpath, b"") or 0,
            {"bytes": 0, "paths": [outpath]},
        ),
    )

    config = {
        "sigwood": {"export_dir": str(tmp_path)},
        "export": {"splunk": {
            "host": "192.0.2.20", "port": 8089,
            "query": {esc_query: {
                "spl": "search x", "output_basename": "safe-export",
            }},
        }},
    }
    exporters.run_export(
        config=config, backend=None, query_names=[esc_query],
        since=datetime(2026, 6, 1, tzinfo=timezone.utc),
        until=datetime(2026, 6, 2, tzinfo=timezone.utc),
        out=None, verbose=False,
    )
    out = capsys.readouterr().out
    assert ESC not in out
    # Both the descriptor and query rendered (non-vacuous).
    assert "hostdesc" in out
    assert "qname" in out


def test_cloudtrail_unreadable_object_strips_control(monkeypatch, capsys) -> None:
    # cloudtrail.py:419 - a corrupt S3 object prints its key AND the exception.
    # Focused backend unit: a FakeS3Client lists one ESC-keyed object whose body
    # is not valid gzip, so the corrupt-envelope arm fires.
    from tests._cloudtrail_fakes import FakeS3Client

    base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    esc_key = base + _esc(ext=".json.gz")
    client = FakeS3Client()
    client.add_object(esc_key, b"this is not gzip data")

    if ct.boto3 is None:
        monkeypatch.setattr(ct, "boto3", types.SimpleNamespace(client=None))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    ct.fetch(
        {}, cfg,
        datetime(2026, 6, 1, tzinfo=timezone.utc),
        datetime(2026, 6, 2, tzinfo=timezone.utc),
        verbose=False, skip_confirm=True,
    )
    err = capsys.readouterr().err
    assert ESC not in err
    assert _STRIPPED in err
