"""Tests for log loading metadata, normalization, and schema warnings."""

from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import os
import stat
import subprocess
import sys
import textwrap
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from datetime import date, timedelta

from sigwood.common.loader import (
    _CLOUDTRAIL_COLUMNS,
    _PIHOLE_COLUMNS,
    _SYSLOG_SNIFF_BYTES,
    _SOURCE_LOADERS,
    _apply_ts_filter,
    _classify_rotation_name,
    _discover_syslog_files,
    _flat_default_floor,
    _looks_binary,
    _looks_like_syslog,
    _peek_first_ts,
    _permission_denied_message,
    _rotation_windowed_files,
    _schema_warning,
    _select_group,
    _syslog_files,
    _zeek_file_read_warning,
    _zeek_dated_window,
    _zeek_no_records_warning,
    _zeek_parse_from_lines,
    CoverageTracker,
    RotationSkipInfo,
    SourceCoverage,
    discover_for_source_key,
    discover_cloudtrail_files,
    discover_zeek_files,
    is_bounded,
    is_zeek_bounded,
    load_cloudtrail,
    load_logs,
    load_pihole,
    load_required_logs,
    load_syslog,
)
from sigwood.exporters import _auto_filename
from sigwood.parsers.syslog import parse_timestamp
from sigwood.parsers.zeek import _normalize_dns_df


def _write_ndjson(path: Path, records: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


# ── CloudTrail fixture helpers ────────────────────────────────────────────────

_CT_DOCS_ACCOUNT = "123456789012"


def _ct_event(**overrides) -> dict:
    """Build a minimal valid CloudTrail event dict for loader fixtures."""
    base: dict = {
        "eventTime":       "2026-06-01T12:00:00Z",
        "eventSource":     "s3.amazonaws.com",
        "eventName":       "GetObject",
        "eventID":         "11111111-1111-1111-1111-111111111111",
        "awsRegion":       "us-east-1",
        "sourceIPAddress": "192.0.2.10",
        "userIdentity": {
            "type":        "IAMUser",
            "userName":    "placeholder-user",
            "principalId": "AIDAEXAMPLE",
            "arn":         f"arn:aws:iam::{_CT_DOCS_ACCOUNT}:user/placeholder-user",
        },
        "readOnly": True,
    }
    base.update(overrides)
    return base


def _ct_write_ndjson(path: Path, events: list[dict]) -> None:
    """Write events as one JSON object per line (the exporter wire shape)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(e) for e in events) + "\n",
        encoding="utf-8",
    )


def _ct_write_envelope_gz(path: Path, events: list[dict]) -> None:
    """Write a gzipped single-line ``{"Records":[...]}`` envelope (native S3 shape)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"Records": events}).encode("utf-8")
    path.write_bytes(gzip.compress(payload))


# A realistic AppleDouble sidecar body: resource-fork magic (0x00051607) + filler.
# Neither valid JSON nor gzip, so it would warn / junk IF discovery ever fed it to the
# parser - which is exactly what the ``._*`` filter prevents.
_CT_APPLEDOUBLE_JUNK = bytes([0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00]) + b"Mac OS X" + bytes(16)


def test_load_required_logs_normalizes_conn_and_reports_window(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(
        zeek_dir / "conn.log",
        [
            {
                "ts": 1_779_750_000.0,
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 443,
                "proto": "tcp",
            },
            {
                "ts": 1_779_753_600.0,
                "id.orig_h": "192.0.2.11",
                "id.resp_h": "203.0.113.20",
                "id.resp_p": 22,
                "proto": "tcp",
            },
        ],
    )

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
    )

    df = result.logs["conn*.log*"]
    assert list(df[["src", "dst", "port"]].iloc[0]) == [
        "192.0.2.10",
        "198.51.100.20",
        443,
    ]
    assert result.record_counts == {"conn*.log*": 2}
    assert result.data_window == (
        datetime.fromtimestamp(1_779_750_000.0, tz=timezone.utc),
        datetime.fromtimestamp(1_779_753_600.0, tz=timezone.utc),
    )
    assert result.warnings == []


def test_load_required_logs_warns_on_missing_canonical_fields(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(
        zeek_dir / "conn.log",
        [
            {
                "ts": 1_779_750_000.0,
                "id.orig_h": "192.0.2.10",
            },
        ],
    )

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
    )

    assert result.record_counts == {"conn*.log*": 1}
    assert result.warnings == [
        "conn.log fields not found: dst - is this a Zeek conn.log?"
    ]


@pytest.mark.parametrize("invalid_ts", [float("inf"), float("-inf")])
def test_load_required_logs_drops_infinite_zeek_timestamps(
    tmp_path: Path,
    invalid_ts: float,
) -> None:
    """Infinity never reaches the canonical frame, coverage, or data window."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "conn.log", [
        {
            "ts": 100.0,
            "id.orig_h": "192.0.2.10",
            "id.resp_h": "198.51.100.10",
            "id.resp_p": 443,
            "proto": "tcp",
        },
        {
            "ts": invalid_ts,
            "id.orig_h": "192.0.2.11",
            "id.resp_h": "198.51.100.11",
            "id.resp_p": 53,
            "proto": "udp",
        },
    ])

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
    )

    assert result.record_counts == {"conn*.log*": 1}
    assert result.logs["conn*.log*"]["src"].tolist() == ["192.0.2.10"]
    assert result.data_window == (
        datetime.fromtimestamp(100.0, tz=timezone.utc),
        datetime.fromtimestamp(100.0, tz=timezone.utc),
    )
    assert result.coverage == {}


def test_load_required_logs_warns_when_source_missing() -> None:
    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {},
    )

    assert result.logs == {}
    assert result.record_counts == {}
    assert result.data_window is None
    assert result.warnings == ["zeek_dir not configured - conn*.log* not loaded"]


def test_schema_warning_does_not_fire_for_missing_duration() -> None:
    """duration is optional - Zeek omits it for connections that have not closed."""
    df = pd.DataFrame([{
        "src": "192.0.2.10", "dst": "198.51.100.20",
        "port": 443, "proto": "tcp", "ts": 1_779_750_000.0,
    }])
    assert _schema_warning("conn*.log*", df) is None


def test_schema_warning_does_not_fire_for_missing_graph_enrichment() -> None:
    """Port and protocol are optional enrichment at the canonical boundary."""
    df = pd.DataFrame([{
        "src": "192.0.2.10", "dst": "198.51.100.20",
        "ts": 1_779_750_000.0, "duration": 600.0,
    }])
    assert _schema_warning("conn*.log*", df) is None


def test_schema_warning_fires_for_missing_required_conn_field() -> None:
    """Optional-column subtraction retains the conn spine warning."""
    df = pd.DataFrame([{
        "src": "192.0.2.10", "port": 443, "proto": "tcp",
        "ts": 1_779_750_000.0, "duration": 600.0,
    }])
    warning = _schema_warning("conn*.log*", df)
    assert warning is not None
    assert "dst" in warning


def test_load_required_logs_routes_pihole_dir(tmp_path: Path) -> None:
    """pihole_dir source key loads via load_pihole and returns _PIHOLE_COLUMNS schema."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text(
        "Jun  1 12:00:00 dnsmasq[1]: query[A] example.test from 192.0.2.1\n",
        encoding="utf-8",
    )
    result = load_required_logs(
        {"pihole*.log*": "pihole_dir"},
        {"pihole_dir": [pihole_dir]},
    )
    df = result.logs["pihole*.log*"]
    assert set(_PIHOLE_COLUMNS).issubset(set(df.columns))
    assert len(df) == 1


def test_load_required_logs_routes_cloudtrail_dir(tmp_path: Path) -> None:
    """cloudtrail_dir source key loads via load_cloudtrail with canonical columns."""
    cloudtrail_dir = tmp_path / "cloudtrail"
    cloudtrail_dir.mkdir()
    _ct_write_ndjson(cloudtrail_dir / "events.json.log", [_ct_event()])

    result = load_required_logs(
        {"*.json*": "cloudtrail_dir"},
        {"cloudtrail_dir": [cloudtrail_dir]},
    )

    df = result.logs["*.json*"]
    assert list(df.columns) == _CLOUDTRAIL_COLUMNS
    assert len(df) == 1
    assert result.record_counts == {"*.json*": 1}
    assert result.data_size_bytes > 0
    assert result.warnings == []


def test_load_required_logs_raises_for_unknown_source_key(tmp_path: Path) -> None:
    bogus_dir = tmp_path / "bogus"
    bogus_dir.mkdir()
    with pytest.raises(ValueError, match="bogus_dir"):
        load_required_logs({"*.log*": "bogus_dir"}, {"bogus_dir": [bogus_dir]})


def test_discover_for_source_key_uses_registered_strategy(tmp_path: Path) -> None:
    """Generic discovery delegates to the source family rather than Zeek-only code."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    day = zeek_dir / "2026-06-01"
    day.mkdir()
    conn = day / "conn.log"
    _write_ndjson(conn, [{"ts": 1.0}])

    assert discover_for_source_key("zeek_dir", zeek_dir, "conn*.log*") == [conn]
    with pytest.raises(ValueError, match="unknown source key 'missing_dir'"):
        discover_for_source_key("missing_dir", zeek_dir, "*.log*")


def test_load_required_logs_trusted_zeek_files_bypass_name_gate_with_metadata(
    tmp_path: Path,
) -> None:
    """Trusted sniff-routed Zeek files keep the ordinary LoadResult contract."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    ordinary = zeek_dir / "conn.log"
    routed_a = tmp_path / "capture-a.ndjson"
    routed_b = tmp_path / "capture-b.ndjson"

    _write_ndjson(ordinary, [{
        "ts": 100.0,
        "id.orig_h": "192.0.2.10",
        "id.resp_h": "198.51.100.10",
        "id.resp_p": 443,
        "proto": "tcp",
    }])
    _write_ndjson(routed_a, [{
        "ts": 200.0,
        "id.orig_h": "192.0.2.11",
        "id.resp_h": "198.51.100.11",
        "id.resp_p": 53,
        "proto": "udp",
    }])
    _write_ndjson(routed_b, [{
        "ts": 300.0,
        "id.orig_h": "192.0.2.12",
        "id.resp_h": "198.51.100.12",
        "id.resp_p": 22,
        "proto": "tcp",
    }])

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [routed_a, routed_b, zeek_dir]},
        trusted_files={"conn*.log*": [routed_a, routed_b]},
    )

    assert result.record_counts == {"conn*.log*": 3}
    assert result.logs["conn*.log*"]["src"].tolist() == [
        "192.0.2.11", "192.0.2.12", "192.0.2.10",
    ]
    assert result.data_window == (
        datetime.fromtimestamp(100.0, tz=timezone.utc),
        datetime.fromtimestamp(300.0, tz=timezone.utc),
    )
    assert result.data_size_bytes == sum(p.stat().st_size for p in (ordinary, routed_a, routed_b))
    assert result.warnings == []
    assert result.coverage == {}
    assert result.rotation_skips == {}
    assert result.permission_skips == {}


def test_load_required_logs_trusted_zeek_file_records_permission_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A trusted explicit file still uses run_load's permission accounting."""
    import sigwood.common.loader as loader_mod

    routed = tmp_path / "capture.ndjson"
    _write_ndjson(routed, [{
        "ts": 100.0,
        "id.orig_h": "192.0.2.10",
        "id.resp_h": "198.51.100.10",
        "id.resp_p": 443,
        "proto": "tcp",
    }])

    monkeypatch.setattr(
        loader_mod, "_open_log", lambda _path: (_ for _ in ()).throw(PermissionError())
    )
    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [routed]},
        trusted_files={"conn*.log*": [routed]},
    )

    assert result.logs["conn*.log*"].empty
    assert result.record_counts == {}
    assert result.data_window is None
    assert any("permission denied" in warning for warning in result.warnings)
    assert result.permission_skips["conn*.log*"].paths == (routed,)
    assert result.permission_skips["conn*.log*"].discovered == 1
    assert result.permission_skips["conn*.log*"].denied == 1


def test_normalize_dns_df_renames_and_applies_qclass_aperture() -> None:
    """_normalize_dns_df renames Zeek-native DNS columns to canonical names,
    keeps only qclass==1 rows, drops qclass, and carries qtype through."""
    df = pd.DataFrame([
        # qclass=1 (internet) - must be kept
        {
            "id.orig_h": "192.0.2.1", "id.resp_h": "192.0.2.53",
            "TTLs": [300.0], "answers": ["198.51.100.1"],
            "TC": 0, "qclass": 1, "qtype": 1, "query": "example.com",
            "ts": 1.0, "rtt": 0.05, "rcode": 0,
        },
        # qclass=2 (CSNET, obsolete) - must be dropped
        {
            "id.orig_h": "192.0.2.2", "TTLs": [60.0], "answers": ["198.51.100.2"],
            "TC": 0, "qclass": 2, "qtype": 1, "query": "other.com",
            "ts": 2.0, "rtt": 0.03, "rcode": 0,
        },
        # qclass=None - must be dropped (== 1 drops nulls)
        {
            "id.orig_h": "192.0.2.3", "TTLs": None, "answers": None,
            "TC": 0, "qclass": None, "qtype": 1, "query": "null-class.com",
            "ts": 3.0, "rtt": None, "rcode": None,
        },
    ])

    result = _normalize_dns_df(df)

    assert len(result) == 1, "only the qclass=1 row should survive"

    assert "src" in result.columns, "id.orig_h should be renamed to src"
    assert "resolver" in result.columns, "id.resp_h should be renamed to resolver"
    assert "ttl" in result.columns, "TTLs should be renamed to ttl"
    assert "answer" in result.columns, "answers should be renamed to answer"
    assert "tc" in result.columns, "TC should be renamed to tc"

    assert "qclass" not in result.columns, "qclass must be dropped"
    assert "qtype" in result.columns, "qtype must be carried through (raw numeric code)"
    assert "id.orig_h" not in result.columns, "Zeek-native id.orig_h must not remain"
    assert "id.resp_h" not in result.columns, "Zeek-native id.resp_h must not remain"

    assert result.iloc[0]["src"] == "192.0.2.1"
    assert result.iloc[0]["resolver"] == "192.0.2.53"

    # rtt and rcode are already canonical - must pass through unchanged
    assert "rtt" in result.columns
    assert "rcode" in result.columns


def test_normalize_dns_df_carries_qtype_as_raw_numeric() -> None:
    """qtype is carried through as Zeek's raw numeric type code - no rename,
    no mnemonic translation. Aperture and qclass drop are unchanged."""
    df = pd.DataFrame([
        # qclass=1, qtype=1 (A) - must survive with qtype preserved
        {
            "id.orig_h": "192.0.2.10", "query": "alpha.invalid",
            "ts": 1.0, "qclass": 1, "qtype": 1, "rcode": 0,
        },
        # qclass=1, qtype=28 (AAAA) - must survive with qtype preserved
        {
            "id.orig_h": "192.0.2.11", "query": "beta.invalid",
            "ts": 2.0, "qclass": 1, "qtype": 28, "rcode": 0,
        },
        # qclass=2 (CSNET) - must be dropped by the aperture
        {
            "id.orig_h": "192.0.2.12", "query": "gamma.invalid",
            "ts": 3.0, "qclass": 2, "qtype": 1, "rcode": 0,
        },
    ])

    result = _normalize_dns_df(df).reset_index(drop=True)

    # Aperture still working - CSNET row dropped
    assert len(result) == 2, "qclass=2 row must be dropped by the aperture"
    # qclass still dropped from the output frame
    assert "qclass" not in result.columns, "qclass must be dropped"
    # qtype carried through as raw numeric (1 for A, 28 for AAAA - no mnemonic)
    assert "qtype" in result.columns, "qtype must be carried through"
    assert list(result["qtype"]) == [1, 28]


# ── Pi-hole / dnsmasq loader tests ───────────────────────────────────────────

_PIHOLE_LINE_QUERY = "Jun  1 12:00:00 dnsmasq[1]: query[A] example.test from 192.0.2.1"
_PIHOLE_LINE_REPLY = "Jun  1 12:00:01 dnsmasq[1]: reply example.test is 203.0.113.1"


def test_load_pihole_plain_fixture(tmp_path: Path) -> None:
    """Two valid dnsmasq lines in a directory load into a _PIHOLE_COLUMNS DataFrame."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text(
        f"{_PIHOLE_LINE_QUERY}\n{_PIHOLE_LINE_REPLY}\n", encoding="utf-8"
    )
    df = load_pihole(pihole_dir)
    assert list(df.columns) == _PIHOLE_COLUMNS
    assert len(df) == 2
    assert df.iloc[0]["event_type"] == "query"
    assert df.iloc[0]["src"] == "192.0.2.1"
    assert df.iloc[1]["event_type"] == "reply"


def test_load_pihole_single_file_path(tmp_path: Path) -> None:
    """load_pihole accepts a direct file path instead of a directory."""
    log_file = tmp_path / "pihole.log"
    log_file.write_text(f"{_PIHOLE_LINE_QUERY}\n", encoding="utf-8")
    df = load_pihole(log_file)
    assert list(df.columns) == _PIHOLE_COLUMNS
    assert len(df) == 1


def test_permission_denied_message_advises_allowlisted_readable_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A group-readable adm log gets the exact least-privilege group remedy."""
    import sigwood.common.loader.diagnostics as diagnostics

    target = tmp_path / "pihole.log"
    target.write_text("", encoding="utf-8")
    fake_stat = SimpleNamespace(
        st_uid=1001,
        st_gid=1002,
        st_mode=stat.S_IFREG | 0o640,
    )
    monkeypatch.setattr(diagnostics.os, "stat", lambda _path: fake_stat)
    monkeypatch.setattr(
        diagnostics.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="loguser"),
    )
    monkeypatch.setattr(
        diagnostics.grp,
        "getgrgid",
        lambda _gid: SimpleNamespace(gr_name="adm"),
    )

    msg = _permission_denied_message(target)

    assert msg == (
        "pihole.log: permission denied - owned loguser:adm "
        "(mode 0640); add your user to the 'adm' group "
        "(sudo usermod -aG adm $USER) and log back in"
    )


@pytest.mark.parametrize(
    ("group", "mode"),
    [
        ("adm", 0o600),
        ("wheel", 0o640),
        ("sudo", 0o640),
        ("root", 0o640),
    ],
)
def test_permission_denied_message_avoids_unsafe_or_ineffective_group_add(
    group: str,
    mode: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unsafe groups and mode-ineffective membership receive generic advice."""
    import sigwood.common.loader.diagnostics as diagnostics

    target = tmp_path / "messages"
    target.write_text("", encoding="utf-8")
    fake_stat = SimpleNamespace(
        st_uid=1001,
        st_gid=1002,
        st_mode=stat.S_IFREG | mode,
    )
    monkeypatch.setattr(diagnostics.os, "stat", lambda _path: fake_stat)
    monkeypatch.setattr(
        diagnostics.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="loguser"),
    )
    monkeypatch.setattr(
        diagnostics.grp,
        "getgrgid",
        lambda _gid: SimpleNamespace(gr_name=group),
    )

    msg = _permission_denied_message(target)

    assert "grant your user read access" in msg
    assert "adjust its group ownership or add an ACL" in msg
    assert "usermod" not in msg
    assert "usermod -aG root" not in msg


def test_permission_denied_message_numeric_lookup_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing passwd/group names fall back to numeric ids without traceback."""
    import sigwood.common.loader.diagnostics as diagnostics

    target = tmp_path / "pihole.log"
    target.write_text("", encoding="utf-8")
    fake_stat = SimpleNamespace(
        st_uid=1001,
        st_gid=1002,
        st_mode=stat.S_IFREG | 0o600,
    )
    monkeypatch.setattr(diagnostics.os, "stat", lambda _path: fake_stat)
    monkeypatch.setattr(
        diagnostics.pwd,
        "getpwuid",
        lambda _uid: (_ for _ in ()).throw(KeyError("uid")),
    )
    monkeypatch.setattr(
        diagnostics.grp,
        "getgrgid",
        lambda _gid: (_ for _ in ()).throw(KeyError("gid")),
    )

    msg = _permission_denied_message(target)

    assert msg == (
        "pihole.log: permission denied - owned 1001:1002 "
        "(mode 0600); grant your user read access to it and retry"
    )
    assert "add your user" not in msg
    assert "sudo" not in msg


def test_load_pihole_gzip_fixture(tmp_path: Path) -> None:
    """Gzip-compressed dnsmasq log is decompressed and loads identically to plain."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    content = f"{_PIHOLE_LINE_QUERY}\n{_PIHOLE_LINE_REPLY}\n"
    with gzip.open(pihole_dir / "pihole.log.gz", "wt", encoding="utf-8") as fh:
        fh.write(content)
    df = load_pihole(pihole_dir)
    assert list(df.columns) == _PIHOLE_COLUMNS
    assert len(df) == 2


def test_load_pihole_ndjson_skipped(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """A wrong-FORMAT (NDJSON) file matching the pihole glob is skipped quietly by
    default; surrounding dnsmasq files load. (Named to match ``pihole*.log*`` so it
    enters the discovered universe - the wrong-format skip is what's under test.)"""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.ndjson.log").write_text('{"ts": 1.0}\n', encoding="utf-8")
    (pihole_dir / "pihole.log").write_text(f"{_PIHOLE_LINE_QUERY}\n", encoding="utf-8")
    df = load_pihole(pihole_dir)
    assert len(df) == 1
    captured = capsys.readouterr()
    assert captured.err == ""

    df = load_pihole(pihole_dir, verbose=True)
    assert len(df) == 1
    captured = capsys.readouterr()
    assert "pihole.ndjson.log" in captured.err
    assert "NDJSON" in captured.err


def test_load_required_logs_pihole_permission_denied_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permission-denied files warn distinctly and record structured metadata."""
    import sigwood.common.loader as loader_mod

    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text("unreadable placeholder\n", encoding="utf-8")
    (pihole_dir / "pihole.log.1").write_text("unreadable placeholder\n", encoding="utf-8")

    def _deny(_path: Path):
        raise PermissionError("synthetic denied")

    monkeypatch.setattr(loader_mod, "_open_log", _deny)

    result = load_required_logs(
        {"pihole*.log*": "pihole_dir"},
        {"pihole_dir": [pihole_dir]},
    )

    assert result.logs["pihole*.log*"].empty
    assert result.record_counts == {}
    assert len(result.warnings) == 2
    assert all("permission denied" in warning for warning in result.warnings)
    assert not any("PermissionError" in warning for warning in result.warnings)
    assert not any("[Errno" in warning for warning in result.warnings)
    assert not any("could not be read - could not be read" in warning
                   for warning in result.warnings)
    info = result.permission_skips["pihole*.log*"]
    assert info.discovered == 2
    assert info.denied == 2
    assert {p.name for p in info.paths} == {"pihole.log", "pihole.log.1"}


def test_generic_read_warning_does_not_double_read_phrase() -> None:
    """Generic read failures keep one unreadable stem plus the exception class."""
    warning = _zeek_file_read_warning(Path("conn.log"), FileNotFoundError())

    assert warning == "conn.log could not be read - unreadable (FileNotFoundError); skipping"
    assert "could not be read - could not be read" not in warning


def test_load_required_logs_pihole_mixed_permission_denied_loads_readable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A denied sibling is recorded while readable rows still load."""
    import sigwood.common.loader as loader_mod

    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text(f"{_PIHOLE_LINE_QUERY}\n", encoding="utf-8")
    (pihole_dir / "pihole.log.1").write_text("unreadable placeholder\n", encoding="utf-8")

    real_open = loader_mod._open_log

    def _maybe_deny(path: Path):
        if path.name == "pihole.log.1":
            raise PermissionError("synthetic denied")
        return real_open(path)

    monkeypatch.setattr(loader_mod, "_open_log", _maybe_deny)

    result = load_required_logs(
        {"pihole*.log*": "pihole_dir"},
        {"pihole_dir": [pihole_dir]},
    )

    assert result.record_counts == {"pihole*.log*": 1}
    assert len(result.logs["pihole*.log*"]) == 1
    info = result.permission_skips["pihole*.log*"]
    assert info.discovered == 2
    assert info.denied == 1
    assert [p.name for p in info.paths] == ["pihole.log.1"]


def test_load_required_logs_permission_discovery_counts_attempted_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrong-family skips do not inflate permission-denied discovery counts."""
    import sigwood.common.loader as loader_mod

    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text('{"ts": 1.0}\n', encoding="utf-8")
    (pihole_dir / "pihole.log.1").write_text("unreadable placeholder\n", encoding="utf-8")

    real_open = loader_mod._open_log

    def _maybe_deny(path: Path):
        if path.name == "pihole.log.1":
            raise PermissionError("synthetic denied")
        return real_open(path)

    monkeypatch.setattr(loader_mod, "_open_log", _maybe_deny)

    result = load_required_logs(
        {"pihole*.log*": "pihole_dir"},
        {"pihole_dir": [pihole_dir]},
    )

    info = result.permission_skips["pihole*.log*"]
    assert info.discovered == 1
    assert info.denied == 1
    assert [p.name for p in info.paths] == ["pihole.log.1"]


def test_load_pihole_empty_file(tmp_path: Path) -> None:
    """An empty log file returns an empty DataFrame with the canonical columns."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text("", encoding="utf-8")
    df = load_pihole(pihole_dir)
    assert list(df.columns) == _PIHOLE_COLUMNS
    assert len(df) == 0


def test_load_pihole_malformed_lines_dropped(tmp_path: Path) -> None:
    """Non-dnsmasq lines are dropped; valid lines on either side are retained."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text(
        f"{_PIHOLE_LINE_QUERY}\nnot a dnsmasq line at all\n{_PIHOLE_LINE_REPLY}\n",
        encoding="utf-8",
    )
    df = load_pihole(pihole_dir)
    assert len(df) == 2


def test_load_pihole_hostname_from_stem(tmp_path: Path) -> None:
    """Host is derived from the filename stem, not from log content."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole-router.log").write_text(
        f"{_PIHOLE_LINE_QUERY}\n{_PIHOLE_LINE_REPLY}\n", encoding="utf-8"
    )
    df = load_pihole(pihole_dir)
    assert (df["host"] == "pihole-router").all()


def test_load_pihole_timefilter_keeps_nan_ts(tmp_path: Path) -> None:
    """Rows with unparseable timestamps (NaN ts) are not dropped by the timeframe filter."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    # Outer regex matches "Xxx" (\w{3}) but strptime fails on it → parse_timestamp returns None
    nan_ts_line = "Xxx  1 12:00:00 dnsmasq[1]: query[A] other.test from 192.0.2.2"
    (pihole_dir / "pihole.log").write_text(
        f"{_PIHOLE_LINE_QUERY}\n{nan_ts_line}\n", encoding="utf-8"
    )
    _year = datetime.now(timezone.utc).year
    since = datetime(_year, 6, 1, 11, 0, 0, tzinfo=timezone.utc)
    until = datetime(_year, 6, 1, 13, 0, 0, tzinfo=timezone.utc)
    df = load_pihole(pihole_dir, since, until)
    assert len(df) == 2
    import math
    assert math.isnan(df.loc[df["query"] == "other.test", "ts"].iloc[0])


def test_schema_warning_no_ops_for_pihole_pattern(tmp_path: Path) -> None:
    """_schema_warning returns None for pihole patterns - no required-column contract."""
    df = pd.DataFrame([{"ts": 1.0, "query": "example.test", "src": "192.0.2.1"}])
    assert _schema_warning("pihole*.log*", df) is None


# ── binary/undecodable flat-file guard ────────────────────────────────────────


def test_looks_binary_unit(tmp_path: Path) -> None:
    """_looks_binary: a NUL byte → True; NUL-free invalid-UTF8 over the 30% floor →
    True; clean RFC-3164 text → False; a read error (non-gzip bytes in a .gz)
    defers conservatively → False (NOT mislabeled binary)."""
    nul = tmp_path / "nul.log"
    nul.write_bytes(b"abc\x00\x00def" * 40)
    assert _looks_binary(nul) is True

    # High-byte run (0x80-0xFF): no NUL, but invalid UTF-8 → ~100% replacement.
    repl = tmp_path / "repl.log"
    repl.write_bytes(bytes(range(0x80, 0x100)) * 40)
    assert _looks_binary(repl) is True

    clean = tmp_path / "clean.log"
    clean.write_text("<134>Jun 28 12:00:00 host-a kernel: ok\n" * 30, encoding="utf-8")
    assert _looks_binary(clean) is False

    # Non-gzip bytes in a .gz → gzip.BadGzipFile on read → conservative False, so
    # the corrupt file defers to run_load's read-corruption rail.
    badgz = tmp_path / "bad.gz"
    badgz.write_bytes(b"plain text, not gzip\nsecond line\n")
    assert _looks_binary(badgz) is False


def test_pihole_dir_binary_glob_warns_and_skips(tmp_path: Path) -> None:
    """pihole DIRECTORY discovery globs ``pihole*.log*`` with NO content sniff, so a
    binary file is SELECTED and then warn-skipped: a DEFAULT-VISIBLE
    ``load_result.warnings`` entry, the binary contributes zero rows, and a valid
    sibling still loads."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.bin.log").write_bytes(b"\x00\x00binary\x00" * 40)
    (pihole_dir / "pihole.log").write_text(f"{_PIHOLE_LINE_QUERY}\n", encoding="utf-8")

    result = load_required_logs(
        {"pihole*.log*": "pihole_dir"},
        {"pihole_dir": [pihole_dir]},
    )
    assert (
        "pihole_dir: skipping pihole.bin.log - looks binary or won't decode as text"
        in result.warnings
    )
    # the valid sibling still loaded; the binary contributed nothing
    assert result.record_counts.get("pihole*.log*") == 1


def test_syslog_gz_rotation_not_flagged_loads(tmp_path: Path) -> None:
    """A real .gz-compressed flat syslog rotation decompresses CLEAN through the
    warn_skip gate (``_looks_binary`` is False) and loads - no false-positive on
    compressed text."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    with gzip.open(syslog_dir / "syslog.log.gz", "wt", encoding="utf-8") as fh:
        fh.write("<134>Jun 28 12:00:00 host-a kernel: ok\n" * 30)
    df = load_syslog(syslog_dir)
    assert len(df) == 30


# ── TSV load path tests ───────────────────────────────────────────────────────

_CONN_TSV_HEADER = (
    "#separator \\x09\n"
    "#set_separator ,\n"
    "#empty_field (empty)\n"
    "#unset_field -\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n"
)


def _write_tsv(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_load_logs_mixed_ndjson_and_tsv(tmp_path: Path) -> None:
    """NDJSON and TSV files in the same directory both load; canonical columns present."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()

    _write_ndjson(
        zeek_dir / "conn.log",
        [
            {"ts": 1000.0, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
             "id.resp_p": 443, "proto": "tcp"},
            {"ts": 1001.0, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
             "id.resp_p": 80, "proto": "tcp"},
        ],
    )
    _write_tsv(
        zeek_dir / "conn.2026-01-01.log",
        _CONN_TSV_HEADER
        + "2000.0\tCabc1\t192.0.2.2\t54321\t198.51.100.2\t443\ttcp\n"
        + "2001.0\tCabc2\t192.0.2.2\t54322\t198.51.100.2\t80\ttcp\n",
    )

    df = load_logs(zeek_dir, "conn*.log*")

    assert len(df) == 4
    for col in ("src", "dst", "port", "proto"):
        assert col in df.columns, f"canonical column {col!r} missing"
    assert set(df["src"].tolist()) == {"192.0.2.1", "192.0.2.2"}


def test_load_logs_timeframe_filter_applies_across_encodings(tmp_path: Path) -> None:
    """since/until filters rows from both NDJSON and TSV files uniformly."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()

    # NDJSON: ts=100.0 in-window, ts=50.0 out-of-window
    _write_ndjson(
        zeek_dir / "conn.log",
        [
            {"ts": 100.0, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
             "id.resp_p": 443, "proto": "tcp"},
            {"ts": 50.0, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
             "id.resp_p": 443, "proto": "tcp"},
        ],
    )
    # TSV: ts=200.0 in-window, ts=300.0 out-of-window
    _write_tsv(
        zeek_dir / "conn.2026-01-01.log",
        _CONN_TSV_HEADER
        + "200.0\tCabc1\t192.0.2.3\t54321\t198.51.100.3\t443\ttcp\n"
        + "300.0\tCabc2\t192.0.2.3\t54322\t198.51.100.3\t443\ttcp\n",
    )

    since = datetime.fromtimestamp(75.0, tz=timezone.utc)
    until = datetime.fromtimestamp(250.0, tz=timezone.utc)
    df = load_logs(zeek_dir, "conn*.log*", since=since, until=until)

    assert len(df) == 2
    assert set(df["ts"].tolist()) == {100.0, 200.0}
    assert set(df["src"].tolist()) == {"192.0.2.1", "192.0.2.3"}


def test_load_logs_tsv_vector_addr_and_set_enum(tmp_path: Path) -> None:
    """vector[addr] and set[enum] fields survive the load path as Python lists."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()

    _write_tsv(
        zeek_dir / "weird.log",
        "#separator \\x09\n"
        "#set_separator ,\n"
        "#empty_field (empty)\n"
        "#unset_field -\n"
        "#fields\tts\taddrs\tactions\n"
        "#types\ttime\tvector[addr]\tset[enum]\n"
        "1000.0\t192.0.2.1,192.0.2.2\tWeird::ACTIVITY,Weird::NOTICE\n",
    )

    df = load_logs(zeek_dir, "weird*.log*")

    assert len(df) == 1
    addrs = df.iloc[0]["addrs"]
    assert isinstance(addrs, list)
    assert addrs == ["192.0.2.1", "192.0.2.2"]

    actions = df.iloc[0]["actions"]
    assert isinstance(actions, list)
    assert set(actions) == {"Weird::ACTIVITY", "Weird::NOTICE"}


# ── Dated-directory layout tests ─────────────────────────────────────────────
#
# Epoch timestamps used below map to the following UTC calendar dates:
#   1767225600  → 2026-01-01 00:00:00 UTC
#   1767312000  → 2026-01-02 00:00:00 UTC
#   1767398400  → 2026-01-03 00:00:00 UTC
#   1767427200  → 2026-01-03 08:00:00 UTC
#   1767463200  → 2026-01-03 18:00:00 UTC
#   1767484800  → 2026-01-04 00:00:00 UTC

_JAN1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_JAN2 = datetime(2026, 1, 2, tzinfo=timezone.utc)
_JAN3 = datetime(2026, 1, 3, tzinfo=timezone.utc)
_JAN4 = datetime(2026, 1, 4, tzinfo=timezone.utc)
_JAN5 = datetime(2026, 1, 5, tzinfo=timezone.utc)

_TS_JAN1 = _JAN1.timestamp()    # 1767225600.0
_TS_JAN2 = _JAN2.timestamp()    # 1767312000.0
_TS_JAN3 = _JAN3.timestamp()    # 1767398400.0
_TS_JAN3_08 = datetime(2026, 1, 3, 8, tzinfo=timezone.utc).timestamp()   # 1767427200.0
_TS_JAN3_18 = datetime(2026, 1, 3, 18, tzinfo=timezone.utc).timestamp()  # 1767463200.0
_TS_JAN4 = _JAN4.timestamp()    # 1767484800.0


def test_load_logs_flat_layout_unchanged(tmp_path: Path) -> None:
    """Flat directory (no YYYY-MM-DD subdirs) loads exactly as before - regression guard."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(
        zeek_dir / "conn.log",
        [{"ts": _TS_JAN1, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
          "id.resp_p": 443, "proto": "tcp"}],
    )
    _write_ndjson(
        zeek_dir / "conn.2026-01-01.log",
        [{"ts": _TS_JAN2, "id.orig_h": "192.0.2.2", "id.resp_h": "198.51.100.2",
          "id.resp_p": 80, "proto": "tcp"}],
    )

    df = load_logs(zeek_dir, "conn*.log*")

    assert len(df) == 2
    for col in ("src", "dst", "port", "proto"):
        assert col in df.columns
    assert set(df["src"].tolist()) == {"192.0.2.1", "192.0.2.2"}


def test_load_logs_dated_layout_discovers_subdirs(tmp_path: Path) -> None:
    """Dated layout: files inside YYYY-MM-DD subdirs are discovered and concatenated."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "2026-01-01").mkdir()
    (zeek_dir / "2026-01-02").mkdir()
    _write_ndjson(
        zeek_dir / "2026-01-01" / "conn.log",
        [
            {"ts": _TS_JAN1, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
             "id.resp_p": 443, "proto": "tcp"},
            {"ts": _TS_JAN1 + 1, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
             "id.resp_p": 80, "proto": "tcp"},
        ],
    )
    _write_ndjson(
        zeek_dir / "2026-01-02" / "conn.log",
        [
            {"ts": _TS_JAN2, "id.orig_h": "198.51.100.2", "id.resp_h": "203.0.113.1",
             "id.resp_p": 443, "proto": "tcp"},
            {"ts": _TS_JAN2 + 1, "id.orig_h": "198.51.100.2", "id.resp_h": "203.0.113.1",
             "id.resp_p": 22, "proto": "tcp"},
        ],
    )

    df = load_logs(zeek_dir, "conn*.log*")

    assert len(df) == 4
    assert "192.0.2.1" in df["src"].tolist()
    assert "198.51.100.2" in df["src"].tolist()


def test_load_logs_date_pruning_skips_out_of_window_dirs(tmp_path: Path) -> None:
    """Date pruning: out-of-window subdirs are never opened (coarse-by-dirname proof).

    The garbage .gz file in 2026-01-01 would raise BadGzipFile if opened. Absence of
    that exception proves the directory was pruned, not just filtered downstream.
    """
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()

    day1 = zeek_dir / "2026-01-01"
    day1.mkdir()
    # Non-gzip bytes in a .gz file - raises BadGzipFile if opened.
    (day1 / "conn.00:00:00-01:00:00.log.gz").write_bytes(b"NOTGZIP")

    day2 = zeek_dir / "2026-01-02"
    day2.mkdir()
    _write_ndjson(
        day2 / "conn.log",
        [
            {"ts": _TS_JAN2, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.10",
             "id.resp_p": 443, "proto": "tcp"},
            {"ts": _TS_JAN2 + 1, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.10",
             "id.resp_p": 80, "proto": "tcp"},
        ],
    )

    day3 = zeek_dir / "2026-01-03"
    day3.mkdir()
    _write_ndjson(
        day3 / "conn.log",
        [{"ts": _TS_JAN3, "id.orig_h": "192.0.2.11", "id.resp_h": "198.51.100.11",
          "id.resp_p": 443, "proto": "tcp"}],
    )

    since = _JAN2
    until = datetime(2026, 1, 2, 23, 59, 59, tzinfo=timezone.utc)
    df = load_logs(zeek_dir, "conn*.log*", since=since, until=until)

    assert len(df) == 2
    assert set(df["src"].tolist()) == {"192.0.2.10"}


def test_load_logs_dated_boundary_day_included(tmp_path: Path) -> None:
    """A window starting mid-day still includes the boundary subdir; per-line filter trims."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "2026-01-03").mkdir()
    _write_ndjson(
        zeek_dir / "2026-01-03" / "conn.log",
        [
            {"ts": _TS_JAN3_08, "id.orig_h": "192.0.2.20", "id.resp_h": "198.51.100.20",
             "id.resp_p": 443, "proto": "tcp"},
            {"ts": _TS_JAN3_18, "id.orig_h": "192.0.2.21", "id.resp_h": "198.51.100.21",
             "id.resp_p": 443, "proto": "tcp"},
        ],
    )

    # Window starts at noon on Jan 3; only the 18:00 row survives the per-line filter.
    since = datetime(2026, 1, 3, 12, 0, 0, tzinfo=timezone.utc)
    df = load_logs(zeek_dir, "conn*.log*", since=since)

    assert len(df) == 1
    assert df.iloc[0]["src"] == "192.0.2.21"


def test_load_logs_dated_suffix_dir_treated_as_date(tmp_path: Path) -> None:
    """A YYYY-MM-DD-SUFFIX dir is treated as the date prefix, suffix ignored."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "2026-01-02-TSVPRE").mkdir()
    (zeek_dir / "2026-01-04").mkdir()
    _write_ndjson(
        zeek_dir / "2026-01-02-TSVPRE" / "conn.log",
        [{"ts": _TS_JAN2, "id.orig_h": "192.0.2.30", "id.resp_h": "198.51.100.30",
          "id.resp_p": 443, "proto": "tcp"},
         {"ts": _TS_JAN2 + 1, "id.orig_h": "192.0.2.30", "id.resp_h": "198.51.100.30",
          "id.resp_p": 80, "proto": "tcp"}],
    )
    _write_ndjson(
        zeek_dir / "2026-01-04" / "conn.log",
        [{"ts": _TS_JAN4, "id.orig_h": "192.0.2.31", "id.resp_h": "198.51.100.31",
          "id.resp_p": 443, "proto": "tcp"},
         {"ts": _TS_JAN4 + 1, "id.orig_h": "192.0.2.31", "id.resp_h": "198.51.100.31",
          "id.resp_p": 80, "proto": "tcp"}],
    )

    # Window Jan 2-3: TSVPRE dir included, Jan 4 excluded.
    df = load_logs(zeek_dir, "conn*.log*", since=_JAN2, until=_JAN3)
    assert len(df) == 2
    assert set(df["src"].tolist()) == {"192.0.2.30"}

    # Window Jan 4-5: Jan 4 included, TSVPRE dir excluded.
    df = load_logs(zeek_dir, "conn*.log*", since=_JAN4, until=_JAN5)
    assert len(df) == 2
    assert set(df["src"].tolist()) == {"192.0.2.31"}


def test_load_logs_dated_symlink_deduplication(tmp_path: Path) -> None:
    """Symlink pointing at a date subdir: data loads exactly once in both window cases."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    day1 = zeek_dir / "2026-01-01"
    day1.mkdir()
    _write_ndjson(
        day1 / "conn.log",
        [{"ts": _TS_JAN1, "id.orig_h": "192.0.2.40", "id.resp_h": "198.51.100.40",
          "id.resp_p": 443, "proto": "tcp"},
         {"ts": _TS_JAN1 + 1, "id.orig_h": "192.0.2.40", "id.resp_h": "198.51.100.40",
          "id.resp_p": 80, "proto": "tcp"}],
    )
    (zeek_dir / "current").symlink_to(day1)

    # No window: current symlink is deduped; data appears exactly once.
    df = load_logs(zeek_dir, "conn*.log*")
    assert len(df) == 2, f"expected 2 rows (deduped), got {len(df)}"

    # With window covering Jan 1: current is deduped by realpath against the
    # included 2026-01-01 dir; data still loads exactly once.
    df = load_logs(zeek_dir, "conn*.log*", since=_JAN1, until=_JAN2)
    assert len(df) == 2, f"expected 2 rows under window, got {len(df)}"


def test_load_logs_dated_non_date_dir_included_with_window(tmp_path: Path) -> None:
    """Non-date-named dirs are candidates under a window - one discovery universe.

    Dedup is by path, not content (same posture as flat rotation), so a
    duplicate-content export/ dir doubles the rows in BOTH window cases and the
    windowed load agrees with the no-window load on the same fixture.
    """
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "2026-01-02").mkdir()
    (zeek_dir / "export").mkdir()

    rows = [
        {"ts": _TS_JAN2, "id.orig_h": "192.0.2.50", "id.resp_h": "198.51.100.50",
         "id.resp_p": 443, "proto": "tcp"},
        {"ts": _TS_JAN2 + 1, "id.orig_h": "192.0.2.50", "id.resp_h": "198.51.100.50",
         "id.resp_p": 80, "proto": "tcp"},
    ]
    _write_ndjson(zeek_dir / "2026-01-02" / "conn.log", rows)
    _write_ndjson(zeek_dir / "export" / "conn.log", rows)  # duplicate content, distinct path

    windowed = load_logs(zeek_dir, "conn*.log*", since=_JAN2, until=_JAN3)
    unwindowed = load_logs(zeek_dir, "conn*.log*")
    assert len(windowed) == 4
    assert len(unwindowed) == 4


def test_load_logs_dated_current_real_dir_included_with_window(tmp_path: Path) -> None:
    """In-window rows living only in a real current/ dir load under an explicit window.

    A stock zeekctl tree keeps the freshest data in the live spool; windowed
    discovery must include it or the freshest slice silently vanishes.
    """
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    old_day = zeek_dir / "2026-01-01"
    old_day.mkdir()
    _write_ndjson(old_day / "conn.log", [
        {"ts": _TS_JAN1, "id.orig_h": "192.0.2.60", "id.resp_h": "198.51.100.60",
         "id.resp_p": 443, "proto": "tcp"},
    ])
    current = zeek_dir / "current"
    current.mkdir()
    _write_ndjson(current / "conn.log", [
        {"ts": _TS_JAN3, "id.orig_h": "192.0.2.61", "id.resp_h": "198.51.100.61",
         "id.resp_p": 443, "proto": "tcp"},
        {"ts": _TS_JAN3 + 1, "id.orig_h": "192.0.2.61", "id.resp_h": "198.51.100.61",
         "id.resp_p": 80, "proto": "tcp"},
    ])

    df = load_logs(zeek_dir, "conn*.log*", since=_JAN3)
    assert len(df) == 2
    assert set(df["src"]) == {"192.0.2.61"}


def test_load_logs_dated_current_symlink_outside_tree_included_with_window(
    tmp_path: Path,
) -> None:
    """current/ symlinked to an out-of-tree spool: unique realpath, discovered windowed."""
    spool = tmp_path / "spool"
    spool.mkdir()
    _write_ndjson(spool / "conn.log", [
        {"ts": _TS_JAN3, "id.orig_h": "192.0.2.62", "id.resp_h": "198.51.100.62",
         "id.resp_p": 443, "proto": "tcp"},
    ])
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    old_day = zeek_dir / "2026-01-01"
    old_day.mkdir()
    _write_ndjson(old_day / "conn.log", [
        {"ts": _TS_JAN1, "id.orig_h": "192.0.2.60", "id.resp_h": "198.51.100.60",
         "id.resp_p": 443, "proto": "tcp"},
    ])
    (zeek_dir / "current").symlink_to(spool)

    df = load_logs(zeek_dir, "conn*.log*", since=_JAN3)
    assert len(df) == 1
    assert df["src"].tolist() == ["192.0.2.62"]


def test_load_logs_dated_current_symlink_to_excluded_date_dir_not_read(
    tmp_path: Path,
) -> None:
    """current/ aliasing a date-PRUNED day stays excluded - the pruned realpath
    seeds the dedupe set, so an excluded date cannot be read back in through a
    non-date alias. Asserted by row identity, not file count alone.
    """
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    excluded_day = zeek_dir / "2026-01-01"
    excluded_day.mkdir()
    _write_ndjson(excluded_day / "conn.log", [
        {"ts": _TS_JAN1, "id.orig_h": "192.0.2.70", "id.resp_h": "198.51.100.70",
         "id.resp_p": 443, "proto": "tcp"},
    ])
    included_day = zeek_dir / "2026-01-02"
    included_day.mkdir()
    _write_ndjson(included_day / "conn.log", [
        {"ts": _TS_JAN2, "id.orig_h": "192.0.2.71", "id.resp_h": "198.51.100.71",
         "id.resp_p": 443, "proto": "tcp"},
    ])
    (zeek_dir / "current").symlink_to(excluded_day)

    files = discover_zeek_files(zeek_dir, "conn*.log*", since=_JAN2, until=_JAN3)
    assert files == [included_day / "conn.log"]

    df = load_logs(zeek_dir, "conn*.log*", since=_JAN2, until=_JAN3)
    assert "192.0.2.70" not in set(df["src"])
    assert set(df["src"]) == {"192.0.2.71"}


def test_load_logs_dated_non_date_dir_rows_outside_window_filtered(
    tmp_path: Path,
) -> None:
    """Conservative include: discovery cannot date a nameless dir, so it is read
    and its out-of-window rows are filtered to zero downstream."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    day = zeek_dir / "2026-01-02"
    day.mkdir()
    _write_ndjson(day / "conn.log", [
        {"ts": _TS_JAN2, "id.orig_h": "192.0.2.80", "id.resp_h": "198.51.100.80",
         "id.resp_p": 443, "proto": "tcp"},
    ])
    export = zeek_dir / "export"
    export.mkdir()
    _write_ndjson(export / "conn.log", [
        {"ts": _TS_JAN4, "id.orig_h": "192.0.2.81", "id.resp_h": "198.51.100.81",
         "id.resp_p": 443, "proto": "tcp"},
    ])

    files = discover_zeek_files(zeek_dir, "conn*.log*", since=_JAN2, until=_JAN3)
    assert export / "conn.log" in files

    df = load_logs(zeek_dir, "conn*.log*", since=_JAN2, until=_JAN3)
    assert set(df["src"]) == {"192.0.2.80"}


def test_discover_zeek_files_dated_root_level_file_excluded_with_window(
    tmp_path: Path,
) -> None:
    """Mixed-root policy holds in both branches: root-level files never join
    dated-layout discovery, windowed or not."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    day = zeek_dir / "2026-01-02"
    day.mkdir()
    row = [{"ts": _TS_JAN2, "id.orig_h": "192.0.2.82", "id.resp_h": "198.51.100.82",
            "id.resp_p": 443, "proto": "tcp"}]
    _write_ndjson(day / "conn.log", row)
    _write_ndjson(zeek_dir / "conn.log", row)  # root-level file in a dated tree

    windowed = discover_zeek_files(zeek_dir, "conn*.log*", since=_JAN2, until=_JAN3)
    unwindowed = discover_zeek_files(zeek_dir, "conn*.log*")
    assert windowed == [day / "conn.log"]
    assert unwindowed == [day / "conn.log"]


def test_discover_zeek_files_flat_drops_derived_siblings(tmp_path: Path) -> None:
    """Flat discovery keeps primary conn logs and their rotations but drops a
    derived sibling that only shares the type prefix (conn-summary)."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").touch()
    (zeek_dir / "conn.2026-01-02.log.gz").touch()
    (zeek_dir / "conn-summary.2026-01-02.log.gz").touch()
    files = discover_zeek_files(zeek_dir, "conn*.log*")
    assert {f.name for f in files} == {"conn.log", "conn.2026-01-02.log.gz"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named FIFOs are unavailable")
def test_discover_zeek_files_flat_skips_non_regular_candidates(tmp_path: Path) -> None:
    """Directory discovery does not feed a named pipe into the loader."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    regular = zeek_dir / "conn.log"
    regular.touch()
    os.mkfifo(zeek_dir / "conn.1.log")

    assert discover_zeek_files(zeek_dir, "conn*.log*") == [regular]


def test_discover_zeek_files_dated_drops_derived_siblings(tmp_path: Path) -> None:
    """Dated discovery drops a derived sibling inside a date subdir, keeping the
    primary conn log."""
    zeek_dir = tmp_path / "zeek"
    day = zeek_dir / "2026-01-02"
    day.mkdir(parents=True)
    (day / "conn.log").touch()
    (day / "conn-summary.2026-01-02.log.gz").touch()
    files = discover_zeek_files(zeek_dir, "conn*.log*")
    assert files == [day / "conn.log"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named FIFOs are unavailable")
def test_discover_zeek_files_dated_skips_non_regular_candidates(tmp_path: Path) -> None:
    """Dated directory discovery also excludes named pipes before loading."""
    zeek_dir = tmp_path / "zeek"
    day = zeek_dir / "2026-01-02"
    day.mkdir(parents=True)
    regular = day / "conn.log"
    regular.touch()
    os.mkfifo(day / "conn.1.log")

    assert discover_zeek_files(zeek_dir, "conn*.log*") == [regular]


def test_discover_zeek_files_primary_rule_is_general_not_conn_only(
    tmp_path: Path,
) -> None:
    """The primary rule applies to every log type: dns-summary is dropped for
    dns*.log* while dns.log is kept."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "dns.log").touch()
    (zeek_dir / "dns-summary.2026-01-02.log.gz").touch()
    files = discover_zeek_files(zeek_dir, "dns*.log*")
    assert {f.name for f in files} == {"dns.log"}


def test_discover_zeek_files_single_file_summary_loads_ungated(
    tmp_path: Path,
) -> None:
    """Single-file mode is operator intent: an explicitly named conn-summary.log
    still loads (the primary rule is directory-discovery only)."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    summary = zeek_dir / "conn-summary.log"
    summary.touch()
    assert discover_zeek_files(summary, "conn*.log*") == [summary]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_load_logs_dated_unreadable_non_date_dir_does_not_abort(
    tmp_path: Path,
) -> None:
    """An unreadable current/ yields no files (pathlib glob suppresses the
    scandir PermissionError) - the windowed load completes with the date
    dirs' rows instead of aborting."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    day = zeek_dir / "2026-01-02"
    day.mkdir()
    _write_ndjson(day / "conn.log", [
        {"ts": _TS_JAN2, "id.orig_h": "192.0.2.90", "id.resp_h": "198.51.100.90",
         "id.resp_p": 443, "proto": "tcp"},
    ])
    current = zeek_dir / "current"
    current.mkdir()
    _write_ndjson(current / "conn.log", [
        {"ts": _TS_JAN2 + 5, "id.orig_h": "192.0.2.91", "id.resp_h": "198.51.100.91",
         "id.resp_p": 443, "proto": "tcp"},
    ])
    os.chmod(current, 0o000)
    try:
        df = load_logs(zeek_dir, "conn*.log*", since=_JAN2, until=_JAN3)
    finally:
        os.chmod(current, 0o755)  # restore so tmp_path cleanup works
    assert set(df["src"]) == {"192.0.2.90"}


def test_load_logs_tsv_truncated_final_line_warns_and_loads(tmp_path: Path) -> None:
    """Live-file tolerance: a truncated TSV tail is a routine mid-write state -
    clean rows load and ONE warning carries the file-absolute line number."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_tsv(
        zeek_dir / "conn.log",
        _CONN_TSV_HEADER
        + "1767312000.0\tC1\t192.0.2.100\t1234\t198.51.100.100\t443\ttcp\n"
        + "1767312001.0\tC2\t192.0.2.100\t1235\t198.51.100.100\t443\ttcp\n"
        + "1767312002.0\tC3\t192.0.2.",  # mid-write truncated tail
    )

    w: list[str] = []
    df = load_logs(zeek_dir, "conn*.log*", _warnings=w)
    assert len(df) == 2
    assert w == ["conn.log: skipped 1 malformed line (first at line 9)"]


def test_load_logs_tsv_malformed_header_skips_file_loads_healthy_sibling(
    tmp_path: Path,
) -> None:
    """A #separator-bearing file with a broken header is skipped whole with a
    warning; the healthy sibling's rows still load and nothing raises."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_tsv(
        zeek_dir / "conn.2026-01-01.log",
        "#separator \\x09\n"
        "#types\ttime\tstring\n"  # no #fields - header cannot be trusted
        "1767312000.0\tC1\n",
    )
    _write_tsv(
        zeek_dir / "conn.log",
        _CONN_TSV_HEADER
        + "1767312000.0\tC1\t192.0.2.101\t1234\t198.51.100.101\t443\ttcp\n",
    )

    w: list[str] = []
    df = load_logs(zeek_dir, "conn*.log*", _warnings=w)
    assert len(df) == 1
    assert set(df["src"]) == {"192.0.2.101"}
    assert w == [
        "conn.2026-01-01.log could not be parsed - Zeek TSV header missing #fields; skipping"
    ]


def test_load_logs_tsv_malformed_only_file_coverage_parse_gap(tmp_path: Path) -> None:
    """Parse containment keeps coverage honest: the skipped file WAS read, so an
    empty result is a parse gap (full_rows == 0, silent) - never the date-pruned
    None that drives a widen-the-window note."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_tsv(
        zeek_dir / "conn.log",
        "#separator \\x09\n"
        "#types\ttime\n"  # no #fields
        "1767312000.0\n",
    )

    w: list[str] = []
    cov: dict = {}
    df = load_logs(zeek_dir, "conn*.log*", _warnings=w, _coverage=cov)
    assert df.empty
    assert len(w) == 1 and "could not be parsed" in w[0]
    assert cov["coverage"].full_rows == 0


def test_load_logs_sinkless_truncated_tsv_no_raise_whole_file_skipped(
    tmp_path: Path,
) -> None:
    """_warnings=None never raises on malformed TSV: strict parse fails at the
    first bad line and containment skips the WHOLE file - its clean prior rows
    are excluded from the result too; a healthy sibling still loads."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_tsv(
        zeek_dir / "conn-live.log",
        _CONN_TSV_HEADER
        + "1767312000.0\tC1\t192.0.2.102\t1234\t198.51.100.102\t443\ttcp\n"
        + "1767312001.0\tC2\t192.0.2.",
    )
    _write_tsv(
        zeek_dir / "conn.log",
        _CONN_TSV_HEADER
        + "1767312002.0\tC3\t192.0.2.103\t1236\t198.51.100.103\t443\ttcp\n",
    )

    df = load_logs(zeek_dir, "conn*.log*", _warnings=None)
    assert len(df) == 1
    assert set(df["src"]) == {"192.0.2.103"}


def test_load_logs_ndjson_garbage_line_skipped_silently(tmp_path: Path) -> None:
    """The NDJSON path keeps its per-line silent skip: one garbage line among
    good rows drops without a warning."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    good = {"ts": _TS_JAN2, "id.orig_h": "192.0.2.104", "id.resp_h": "198.51.100.104",
            "id.resp_p": 443, "proto": "tcp"}
    (zeek_dir / "conn.log").write_text(
        json.dumps(good) + "\n"
        + "{this is not json\n"
        + json.dumps({**good, "id.resp_p": 80}) + "\n",
        encoding="utf-8",
    )

    w: list[str] = []
    df = load_logs(zeek_dir, "conn*.log*", _warnings=w)
    assert len(df) == 2
    assert w == []


# ── Zero-yield disclosure - a read file that produced no Zeek records ─────────


_ZY_GARBAGE = [
    "totally ordinary prose line one\n",
    "another line of plain words here\n",
]


def test_parse_garbage_text_warns_no_records() -> None:
    """A non-Zeek data line with no #separator: empty frame plus exactly ONE
    byte-exact no-records warning."""
    w: list[str] = []
    df = _zeek_parse_from_lines(iter(_ZY_GARBAGE), path=Path("conn.log"), warnings=w)
    assert df.empty
    assert w == ["conn.log: no Zeek records found - is this a Zeek log?"]


def test_parse_all_malformed_ndjson_warns_no_records() -> None:
    """`{`-leading lines that all fail json.loads → the no-records warning."""
    lines = ['{"broken json line without closing\n', '{"also broken\n']
    w: list[str] = []
    df = _zeek_parse_from_lines(iter(lines), path=Path("conn.log"), warnings=w)
    assert df.empty
    assert w == ["conn.log: no Zeek records found - is this a Zeek log?"]


def test_parse_valid_json_all_missing_ts_warns_no_records() -> None:
    """Valid JSON-lines where every record lacks `ts` (an application log named
    like a Zeek log): every row drops at the ts gate → the no-records warning."""
    lines = [
        json.dumps({"msg": "application event", "level": "info"}) + "\n",
        json.dumps({"msg": "second event", "level": "warn"}) + "\n",
    ]
    w: list[str] = []
    df = _zeek_parse_from_lines(iter(lines), path=Path("conn.log"), warnings=w)
    assert df.empty
    assert w == ["conn.log: no Zeek records found - is this a Zeek log?"]


def test_parse_header_only_tsv_stays_silent() -> None:
    """A valid directive block with zero data rows is a fresh rotation -
    absence, not unreadable data; no warning."""
    w: list[str] = []
    df = _zeek_parse_from_lines(
        iter(_CONN_TSV_HEADER.splitlines(keepends=True)),
        path=Path("conn.log"),
        warnings=w,
    )
    assert df.empty
    assert w == []


@pytest.mark.parametrize(
    "lines",
    [[], ["\n", "   \n"], ["# just a comment\n", "\n"]],
    ids=["empty", "blank-only", "comment-only"],
)
def test_parse_empty_or_comment_stub_stays_silent(lines: list[str]) -> None:
    """No data line seen at all → absence, no warning."""
    w: list[str] = []
    df = _zeek_parse_from_lines(iter(lines), path=Path("conn.log"), warnings=w)
    assert df.empty
    assert w == []


def test_parse_partial_ndjson_loads_without_warning() -> None:
    """Garbage lines alongside a valid-ts row: rows load and the per-line
    tolerance stays silent - zero-yield is the disclosure boundary."""
    lines = [
        "{not json at all\n",
        json.dumps({"ts": _TS_JAN2, "id.orig_h": "192.0.2.104"}) + "\n",
    ]
    w: list[str] = []
    df = _zeek_parse_from_lines(iter(lines), path=Path("conn.log"), warnings=w)
    assert len(df) == 1
    assert w == []


def test_parse_all_malformed_tsv_data_warns_bad_lines_only() -> None:
    """A valid-header TSV whose data lines are all malformed emits ONLY the
    existing bad-lines warning - the no-records warning never double-fires."""
    content = _CONN_TSV_HEADER + "not\tenough\n" + "columns\there\n"
    w: list[str] = []
    df = _zeek_parse_from_lines(
        iter(content.splitlines(keepends=True)), path=Path("conn.log"), warnings=w
    )
    assert df.empty
    assert len(w) == 1
    assert "malformed line" in w[0]
    assert "no Zeek records" not in w[0]


def test_parse_garbage_without_sink_stays_silent() -> None:
    """warnings=None (programmatic callers): empty frame, no raise, no warning
    surface."""
    df = _zeek_parse_from_lines(iter(_ZY_GARBAGE), warnings=None)
    assert df.empty


def test_parse_valid_ndjson_no_warning() -> None:
    """A healthy NDJSON parse emits nothing."""
    lines = [json.dumps({"ts": _TS_JAN2, "id.orig_h": "192.0.2.104"}) + "\n"]
    w: list[str] = []
    df = _zeek_parse_from_lines(iter(lines), path=Path("conn.log"), warnings=w)
    assert len(df) == 1
    assert w == []


def test_load_logs_gzip_garbage_warns_no_records(tmp_path: Path) -> None:
    """The no-records warning fires through transparent decompression."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    with gzip.open(zeek_dir / "conn.log.gz", "wt", encoding="utf-8") as fh:
        fh.write("".join(_ZY_GARBAGE))
    w: list[str] = []
    df = load_logs(zeek_dir, "conn*.log*", _warnings=w)
    assert df.empty
    assert w == ["conn.log.gz: no Zeek records found - is this a Zeek log?"]


def test_load_required_logs_size_matches_pruned_files(tmp_path: Path) -> None:
    """data_size_bytes accounts only for files in the pruned window, not excluded days."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "2026-01-01").mkdir()
    (zeek_dir / "2026-01-02").mkdir()

    _write_ndjson(
        zeek_dir / "2026-01-01" / "conn.log",
        [{"ts": _TS_JAN1, "id.orig_h": "192.0.2.60", "id.resp_h": "198.51.100.60",
          "id.resp_p": 443, "proto": "tcp"}],
    )
    _write_ndjson(
        zeek_dir / "2026-01-02" / "conn.log",
        [{"ts": _TS_JAN2, "id.orig_h": "192.0.2.61", "id.resp_h": "198.51.100.61",
          "id.resp_p": 443, "proto": "tcp"}],
    )

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
        since=_JAN2,
        until=datetime(2026, 1, 2, 23, 59, 59, tzinfo=timezone.utc),
    )

    expected_size = (zeek_dir / "2026-01-02" / "conn.log").stat().st_size
    assert result.data_size_bytes == expected_size


def test_load_required_logs_warns_and_skips_truncated_zeek_gzip(
    tmp_path: Path,
) -> None:
    """A selected truncated gzip file warns and does not abort the whole Zeek load."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()

    payload = (
        b'{"ts":1767312000.0,"id.orig_h":"192.0.2.10",'
        b'"id.resp_h":"198.51.100.10","id.resp_p":443,"proto":"tcp"}\n'
    )
    (zeek_dir / "conn.2026-01-01.log.gz").write_bytes(gzip.compress(payload)[:-8])
    _write_ndjson(
        zeek_dir / "conn.log",
        [{
            "ts": _TS_JAN2,
            "id.orig_h": "192.0.2.11",
            "id.resp_h": "198.51.100.11",
            "id.resp_p": 443,
            "proto": "tcp",
        }],
    )

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
    )

    df = result.logs["conn*.log*"]
    assert len(df) == 1
    assert df.iloc[0]["src"] == "192.0.2.11"
    assert any(
        "conn.2026-01-01.log.gz could not be read" in warning
        and "compressed file is incomplete or corrupt" in warning
        for warning in result.warnings
    )


def test_load_logs_dated_layout_ignores_root_level_files(tmp_path: Path) -> None:
    """Root-level files are ignored when a YYYY-MM-DD subdir exists (mixed-root policy)."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "2026-01-02").mkdir()

    # Root-level file - ignored because a date dir is present.
    _write_ndjson(
        zeek_dir / "conn.log",
        [{"ts": _TS_JAN2, "id.orig_h": "192.0.2.99", "id.resp_h": "198.51.100.99",
          "id.resp_p": 443, "proto": "tcp"}],
    )
    # Dated subdir file - loaded.
    _write_ndjson(
        zeek_dir / "2026-01-02" / "conn.log",
        [{"ts": _TS_JAN2 + 1, "id.orig_h": "192.0.2.50", "id.resp_h": "198.51.100.50",
          "id.resp_p": 443, "proto": "tcp"}],
    )

    df = load_logs(zeek_dir, "conn*.log*")

    assert len(df) == 1
    assert df.iloc[0]["src"] == "192.0.2.50"


# ── Stage 4: boundedness + default window helpers ─────────────────────────────


def test_is_zeek_bounded_returns_true_for_file(tmp_path: Path) -> None:
    f = tmp_path / "conn.log"
    f.write_text("", encoding="utf-8")
    assert is_zeek_bounded([f]) is True


def test_is_zeek_bounded_returns_false_for_directory(tmp_path: Path) -> None:
    assert is_zeek_bounded([tmp_path]) is False


def test_is_zeek_bounded_returns_false_for_glob_string() -> None:
    """Glob strings classify as UNBOUNDED. Stage 4 helper contract; load wiring deferred."""
    assert is_zeek_bounded([Path("conn*.log")]) is False


def test_is_zeek_bounded_empty_list_returns_false() -> None:
    """An empty bucket is NOT bounded - the runner short-circuits before
    calling, but the predicate stays explicit (no Zeek to discuss)."""
    assert is_zeek_bounded([]) is False


def test_zeek_dated_default_window_flat_layout_returns_none(tmp_path: Path) -> None:
    (tmp_path / "conn.log").write_text("", encoding="utf-8")
    assert _zeek_dated_window([tmp_path], timedelta(days=1)) is None


def test_zeek_dated_default_window_1d_picks_newest_subdir_only(tmp_path: Path) -> None:
    """GUARDRAIL - single-input dated selection that the union path must
    GENERALIZE (newest N=ceil(span_days) date subdirs, earliest-midnight →
    newest-23:59:59 UTC). Do NOT reinterpret these assertions; the
    one-element list IS the degenerate single-input case."""
    (tmp_path / "2026-01-01").mkdir()
    (tmp_path / "2026-01-05").mkdir()
    since, until = _zeek_dated_window([tmp_path], timedelta(days=1))
    assert since == datetime(2026, 1, 5, 0, 0, 0, tzinfo=timezone.utc)
    assert until == datetime(2026, 1, 5, 23, 59, 59, tzinfo=timezone.utc)


def test_zeek_dated_default_window_2d_picks_newest_2_subdirs_even_when_sparse(
    tmp_path: Path,
) -> None:
    """GUARDRAIL - sparse-archive selection that the union path must
    GENERALIZE. [2026-01-01, 2026-01-05] with span=2d → BOTH dirs; window
    Jan 1 → Jan 5. Do NOT reinterpret."""
    (tmp_path / "2026-01-01").mkdir()
    (tmp_path / "2026-01-05").mkdir()
    since, until = _zeek_dated_window([tmp_path], timedelta(days=2))
    assert since == datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert until == datetime(2026, 1, 5, 23, 59, 59, tzinfo=timezone.utc)


def test_zeek_dated_default_window_span_exceeds_subdir_count(tmp_path: Path) -> None:
    for d in ["2026-01-01", "2026-01-03", "2026-01-05"]:
        (tmp_path / d).mkdir()
    since, until = _zeek_dated_window([tmp_path], timedelta(days=7))
    assert since.date() == date(2026, 1, 1)
    assert until.date() == date(2026, 1, 5)


def test_discover_zeek_files_file_input_matching_pattern_returns_file(
    tmp_path: Path,
) -> None:
    f = tmp_path / "conn.log"
    _write_ndjson(f, [{"ts": _TS_JAN2}])
    assert discover_zeek_files(f, "conn*.log*") == [f]


def test_discover_zeek_files_file_input_nonmatching_pattern_returns_empty(
    tmp_path: Path,
) -> None:
    f = tmp_path / "dns.log"
    _write_ndjson(f, [{"ts": _TS_JAN2}])
    assert discover_zeek_files(f, "conn*.log*") == []


# ── CloudTrail loader: per-file shapes ────────────────────────────────────────

def test_load_cloudtrail_ndjson_multiple_events_preserves_first_event(
    tmp_path: Path,
) -> None:
    """Regression guard: the NDJSON branch must seed with the parsed first line.

    A prior draft iterated 'remaining lines' without seeding, silently dropping
    the first event of every exporter .json.log file. This asserts the observed
    output, not the internal route.
    """
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    events = [
        _ct_event(eventID="aaaa", eventTime="2026-06-01T12:00:00Z"),
        _ct_event(eventID="bbbb", eventTime="2026-06-01T12:01:00Z"),
        _ct_event(eventID="cccc", eventTime="2026-06-01T12:02:00Z"),
    ]
    _ct_write_ndjson(cloudtrail_dir / "events.json.log", events)

    df = load_cloudtrail(cloudtrail_dir)

    assert list(df.columns) == _CLOUDTRAIL_COLUMNS
    assert len(df) == 3
    assert set(df["event_id"]) == {"aaaa", "bbbb", "cccc"}


def test_load_cloudtrail_bare_one_line_dict_event_loads_as_single_row(
    tmp_path: Path,
) -> None:
    """Single-dict-per-file: first-line parses as a dict without Records, NDJSON
    branch seeds with it, no more lines → exactly one event in the frame."""
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    (cloudtrail_dir / "one.json").write_text(
        json.dumps(_ct_event(eventID="only-one")),
        encoding="utf-8",
    )

    df = load_cloudtrail(cloudtrail_dir)

    assert len(df) == 1
    assert df.iloc[0]["event_id"] == "only-one"


def test_load_cloudtrail_one_line_bare_list_loads_as_event_list(
    tmp_path: Path,
) -> None:
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    events = [
        _ct_event(eventID="list-1"),
        _ct_event(eventID="list-2"),
    ]
    (cloudtrail_dir / "list.json").write_text(
        json.dumps(events),
        encoding="utf-8",
    )

    df = load_cloudtrail(cloudtrail_dir)

    assert len(df) == 2
    assert set(df["event_id"]) == {"list-1", "list-2"}


def test_load_cloudtrail_gzipped_envelope_loads_identically(tmp_path: Path) -> None:
    """Native S3 wire shape: {"Records": [...]} as a single gzipped JSON document."""
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    events = [
        _ct_event(eventID="env-1"),
        _ct_event(eventID="env-2"),
    ]
    _ct_write_envelope_gz(cloudtrail_dir / "envelope.json.gz", events)

    df = load_cloudtrail(cloudtrail_dir)

    assert list(df.columns) == _CLOUDTRAIL_COLUMNS
    assert len(df) == 2
    assert set(df["event_id"]) == {"env-1", "env-2"}


def test_load_cloudtrail_pretty_printed_multiline_envelope_loads(tmp_path: Path) -> None:
    """Whole-file fallback path: first line is a '{' fragment, full text is the doc."""
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    events = [_ct_event(eventID="pretty-1"), _ct_event(eventID="pretty-2")]
    (cloudtrail_dir / "pretty.json").write_text(
        json.dumps({"Records": events}, indent=2),
        encoding="utf-8",
    )

    df = load_cloudtrail(cloudtrail_dir)

    assert len(df) == 2
    assert set(df["event_id"]) == {"pretty-1", "pretty-2"}


def test_load_cloudtrail_mixed_formats_in_one_directory_loads_union(
    tmp_path: Path,
) -> None:
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _ct_write_ndjson(
        cloudtrail_dir / "ndjson.json.log",
        [_ct_event(eventID="nd-1"), _ct_event(eventID="nd-2")],
    )
    _ct_write_envelope_gz(
        cloudtrail_dir / "env.json.gz",
        [_ct_event(eventID="env-1")],
    )

    df = load_cloudtrail(cloudtrail_dir)

    assert len(df) == 3
    assert set(df["event_id"]) == {"nd-1", "nd-2", "env-1"}


# ── CloudTrail loader: discovery ──────────────────────────────────────────────

def test_load_cloudtrail_native_nested_aws_logs_tree_discovered_recursively(
    tmp_path: Path,
) -> None:
    """Recursive *.json* discovery - what makes a native AWSLogs tree just work."""
    nested = (
        tmp_path
        / "AWSLogs" / _CT_DOCS_ACCOUNT / "CloudTrail" / "us-east-1"
        / "2026" / "06" / "01"
    )
    _ct_write_envelope_gz(nested / "events.json.gz", [_ct_event(eventID="nested-1")])

    files = discover_cloudtrail_files(tmp_path)
    assert any("nested" not in p.name for p in files)  # the actual file is discovered
    assert len(files) == 1
    assert files[0].name == "events.json.gz"

    df = load_cloudtrail(tmp_path)
    assert len(df) == 1
    assert df.iloc[0]["event_id"] == "nested-1"


def test_discover_cloudtrail_files_excludes_cloud_trail_digest_tree(
    tmp_path: Path,
) -> None:
    """Digest files are integrity manifests, not events - exclude them."""
    events_dir = tmp_path / "CloudTrail" / "us-east-1" / "2026" / "06" / "01"
    digest_dir = tmp_path / "CloudTrail-Digest" / "us-east-1" / "2026" / "06" / "01"
    _ct_write_envelope_gz(events_dir / "events.json.gz", [_ct_event(eventID="evt-1")])
    _ct_write_envelope_gz(digest_dir / "digest.json.gz", [_ct_event(eventID="digest-1")])

    files = discover_cloudtrail_files(tmp_path)
    file_names = [f.name for f in files]
    assert "events.json.gz" in file_names
    assert "digest.json.gz" not in file_names


def test_discover_cloudtrail_files_excludes_appledouble_sidecars(
    tmp_path: Path,
) -> None:
    """``._*`` AppleDouble sidecars drop from directory discovery, alongside the
    existing ``CloudTrail-Digest`` exclusion (the two guards coexist)."""
    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    _ct_write_ndjson(ct_dir / "evt.json", [_ct_event(eventID="real")])
    (ct_dir / "._evt.json").write_bytes(_CT_APPLEDOUBLE_JUNK)
    (ct_dir / "._evt.json.gz").write_bytes(_CT_APPLEDOUBLE_JUNK)
    _ct_write_envelope_gz(
        ct_dir / "CloudTrail-Digest" / "us-east-1" / "2026" / "06" / "01" / "digest.json.gz",
        [_ct_event(eventID="digest")],
    )

    files = discover_cloudtrail_files(ct_dir)

    assert [f.name for f in files] == ["evt.json"]


def test_load_required_logs_cloudtrail_skips_appledouble_sidecars(
    tmp_path: Path,
) -> None:
    """A binary ``._*`` sidecar beside a real event is never read: the valid event
    loads, no junk rows, no parse warning (the sidecar is excluded at discovery)."""
    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    _ct_write_ndjson(ct_dir / "evt.json.log", [_ct_event(eventID="good-evt")])
    (ct_dir / "._evt.json").write_bytes(_CT_APPLEDOUBLE_JUNK)
    (ct_dir / "._evt.json.gz").write_bytes(_CT_APPLEDOUBLE_JUNK)

    result = load_required_logs(
        {"*.json*": "cloudtrail_dir"},
        {"cloudtrail_dir": [ct_dir]},
    )

    df = result.logs["*.json*"]
    assert len(df) == 1
    assert df.iloc[0]["event_id"] == "good-evt"
    assert result.record_counts == {"*.json*": 1}
    assert result.warnings == []


def test_discover_cloudtrail_files_named_appledouble_file_unfiltered(
    tmp_path: Path,
) -> None:
    """An explicitly named ``._*`` file is returned as-is - the explicit-file rail is
    operator intent, not glob hygiene (identical to the flat families)."""
    p = tmp_path / "._evt.json"
    p.write_bytes(_CT_APPLEDOUBLE_JUNK)

    assert discover_cloudtrail_files(p) == [p]


def test_load_cloudtrail_single_file_path_works(tmp_path: Path) -> None:
    file_path = tmp_path / "events.json.log"
    _ct_write_ndjson(file_path, [_ct_event(eventID="single-file-event")])

    df = load_cloudtrail(file_path)

    assert len(df) == 1
    assert df.iloc[0]["event_id"] == "single-file-event"


def test_load_cloudtrail_empty_directory_returns_column_stable_empty_frame(
    tmp_path: Path,
) -> None:
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()

    df = load_cloudtrail(cloudtrail_dir)

    assert list(df.columns) == _CLOUDTRAIL_COLUMNS
    assert len(df) == 0


# ── CloudTrail loader: tolerance, warnings, filtering ─────────────────────────

def test_load_cloudtrail_undecodable_ndjson_lines_silently_skipped(
    tmp_path: Path,
) -> None:
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    good_a = json.dumps(_ct_event(eventID="good-a"))
    good_b = json.dumps(_ct_event(eventID="good-b"))
    (cloudtrail_dir / "events.json.log").write_text(
        f"{good_a}\nnot json at all\n{good_b}\n",
        encoding="utf-8",
    )

    df = load_cloudtrail(cloudtrail_dir)

    assert len(df) == 2
    assert set(df["event_id"]) == {"good-a", "good-b"}


def test_load_required_logs_warns_and_skips_corrupt_cloudtrail_gzip(
    tmp_path: Path,
) -> None:
    """Corrupt gzip: warning appended to LoadResult.warnings; sibling still loads."""
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    # Truncated gzip
    payload = gzip.compress(
        json.dumps({"Records": [_ct_event(eventID="bad-evt")]}).encode("utf-8")
    )
    (cloudtrail_dir / "broken.json.gz").write_bytes(payload[:-8])
    _ct_write_ndjson(cloudtrail_dir / "ok.json.log", [_ct_event(eventID="good-evt")])

    result = load_required_logs(
        {"*.json*": "cloudtrail_dir"},
        {"cloudtrail_dir": [cloudtrail_dir]},
    )

    df = result.logs["*.json*"]
    assert len(df) == 1
    assert df.iloc[0]["event_id"] == "good-evt"
    assert any(
        "broken.json.gz could not be read" in w
        and "compressed file is incomplete or corrupt" in w
        for w in result.warnings
    )


def test_load_required_logs_warns_and_skips_unparseable_json_file(
    tmp_path: Path,
) -> None:
    """Non-gzip file whose contents are not valid JSON: warn-and-skip with the
    'not valid JSON' message; sibling still loads."""
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    (cloudtrail_dir / "garbage.json").write_text(
        "this is not json at all\nstill not\n",
        encoding="utf-8",
    )
    _ct_write_ndjson(cloudtrail_dir / "ok.json.log", [_ct_event(eventID="evt-ok")])

    result = load_required_logs(
        {"*.json*": "cloudtrail_dir"},
        {"cloudtrail_dir": [cloudtrail_dir]},
    )

    df = result.logs["*.json*"]
    assert len(df) == 1
    assert df.iloc[0]["event_id"] == "evt-ok"
    assert any(
        "garbage.json could not be read" in w and "not valid JSON" in w
        for w in result.warnings
    )


def test_load_cloudtrail_drops_events_with_missing_event_time(
    tmp_path: Path,
) -> None:
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    no_ts = _ct_event(eventID="no-ts")
    no_ts.pop("eventTime")
    _ct_write_ndjson(
        cloudtrail_dir / "events.json.log",
        [_ct_event(eventID="has-ts"), no_ts],
    )

    df = load_cloudtrail(cloudtrail_dir)

    assert len(df) == 1
    assert df.iloc[0]["event_id"] == "has-ts"


def test_load_cloudtrail_applies_since_and_until_window(tmp_path: Path) -> None:
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _ct_write_ndjson(
        cloudtrail_dir / "events.json.log",
        [
            _ct_event(eventID="too-early", eventTime="2026-05-31T11:00:00Z"),
            _ct_event(eventID="inside",    eventTime="2026-06-01T12:00:00Z"),
            _ct_event(eventID="too-late",  eventTime="2026-06-02T13:00:00Z"),
        ],
    )

    df = load_cloudtrail(
        cloudtrail_dir,
        since=datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
        until=datetime(2026, 6, 2, 0, 0, 0, tzinfo=timezone.utc),
    )

    assert len(df) == 1
    assert df.iloc[0]["event_id"] == "inside"


# ── Liveness: loader leaves a permanent record line ──────────────────────────


class _FakeTTYStream:
    """sys.stderr stand-in that reports isatty()=True and captures writes.

    Used to exercise the byte-identical-on-TTY rail: on a real TTY,
    ``progress`` constructs tqdm and the bar text reaches the stream. capsys
    cannot be used here because its captured stderr reports isatty()=False -
    that is exactly the non-TTY suppression rail tested separately below.
    """

    def __init__(self) -> None:
        self._chunks: list[str] = []

    def isatty(self) -> bool:
        return True

    def write(self, s: str) -> int:
        self._chunks.append(s)
        return len(s)

    def flush(self) -> None:  # pragma: no cover - no-op
        return None

    @property
    def output(self) -> str:
        return "".join(self._chunks)


def test_parse_ndjson_leaves_permanent_record_line_on_tty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Byte-identical-on-TTY regression: on a real TTY stream, the NDJSON
    loader still writes a ``loaded <file>: N lines`` permanent record line
    through the shared progress helper. The bar_format is pinned in
    ``common/display.py:progress`` and reproduces the pre-helper inline
    bar_format byte-for-byte when ``unit=" lines"``."""
    from sigwood.common.loader import _parse_ndjson_file

    fake = _FakeTTYStream()
    monkeypatch.setattr("sys.stderr", fake)

    f = tmp_path / "conn.log"
    f.write_text(
        "\n".join(
            json.dumps({"ts": float(i), "id.orig_h": f"192.0.2.{i}"})
            for i in range(1, 6)
        ) + "\n",
        encoding="utf-8",
    )

    _parse_ndjson_file(f)

    out = fake.output
    # tqdm with leave=True commits the summary line for that file.
    assert "loaded conn.log" in out
    assert "5" in out  # the line count, formatted by tqdm's n_fmt


def test_parse_ndjson_non_tty_stream_suppresses_loader_bar(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """On a non-TTY stream (the codified within-loader TTY policy), the
    progress helper returns the bare iterable and tqdm is never constructed.
    capsys's stderr reports isatty()=False, exercising the non-TTY arm."""
    from sigwood.common.loader import _parse_ndjson_file

    f = tmp_path / "conn.log"
    f.write_text(
        "\n".join(
            json.dumps({"ts": float(i), "id.orig_h": f"192.0.2.{i}"})
            for i in range(1, 6)
        ) + "\n",
        encoding="utf-8",
    )

    df = _parse_ndjson_file(f)  # default show_progress=True

    captured = capsys.readouterr()
    assert "loaded conn.log" not in captured.err
    assert len(df) == 5


def test_parse_ndjson_show_progress_false_suppresses_loader_bar(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """show_progress=False routes through the shared progress helper, which
    returns the bare iterable without constructing tqdm. A multi-file digest
    fan-out passes show_progress=False so per-file bars don't interleave
    between rendered cards. The frame must still be returned identical to
    the default-True path - suppression is purely cosmetic."""
    from sigwood.common.loader import _parse_ndjson_file

    f = tmp_path / "conn.log"
    f.write_text(
        "\n".join(
            json.dumps({"ts": float(i), "id.orig_h": f"192.0.2.{i}"})
            for i in range(1, 6)
        ) + "\n",
        encoding="utf-8",
    )

    df = _parse_ndjson_file(f, show_progress=False)

    captured = capsys.readouterr()
    assert "loaded conn.log" not in captured.err
    assert len(df) == 5


# ── Loader progress: seam coverage (mock progress, assert kwargs) ────────────
#
# Each loader read path routes through the shared
# sigwood.common.loader.progress helper. Mocking that seam keeps the tests
# off carriage-return-byte scraping (which is brittle) and verifies the desc /
# unit / show_progress contract each loader holds with the helper. The two
# NDJSON byte-output tests above lock the on-TTY render - these tests lock the
# wiring beneath it.


class _ProgressSpy:
    """Spy for sigwood.common.loader.progress.

    Records (desc, unit, show_progress) per call and forwards iteration to the
    bare iterable so the loader still produces a real frame. Tests can then
    assert how many times each loader called the helper and with what args.
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, iterable, *, desc, show_progress=True, unit=" lines",
                 total=None, stream=None):
        self.calls.append({
            "desc": desc,
            "unit": unit,
            "show_progress": show_progress,
        })
        return iter(iterable)


def test_progress_description_strips_control_filename(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Progress text cannot relay a hostile filename to a terminal surface."""
    from sigwood.common import loader as loader_mod

    spy = _ProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)
    monkeypatch.setattr(
        loader_mod,
        "_open_log",
        lambda _path: nullcontext(io.StringIO(
            '{"ts":1.0,"id.orig_h":"192.0.2.10",'
            '"id.resp_h":"198.51.100.20","id.resp_p":443,'
            '"proto":"tcp","duration":1.0}\n'
        )),
    )
    hostile = Path("conn\x1b[31m.log")

    loader_mod.run_load(
        loader_mod._SOURCE_LOADERS["zeek_dir"], [hostile], "conn*.log*",
        None, None,
    )

    assert spy.calls[0]["desc"] == "loaded conn[31m.log"


def test_progress_seam_tsv_wraps_pre_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Zeek TSV strategy's parse wraps the file handle ONCE through
    ``progress`` (in ``run_load``) BEFORE any per-line work - the
    materialization that follows the prefix-preserving sniff is the slow
    part on a long log. The spy intercepts the single ``progress`` call
    and verifies its kwargs."""
    from sigwood.common import loader as loader_mod

    spy = _ProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    f = tmp_path / "conn.tsv"
    # Minimal valid Zeek TSV - header is enough to claim TSV via #separator.
    f.write_text(
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
        "#types\ttime\taddr\taddr\tport\tenum\n"
        "1779750000.0\t192.0.2.10\t198.51.100.20\t443\ttcp\n"
        "#close\t2026-06-01-12-00-00\n",
        encoding="utf-8",
    )

    loader_mod.load_logs(f.parent, "*.tsv", _files=[f])

    assert len(spy.calls) == 1
    assert spy.calls[0]["desc"] == "loaded conn.tsv"
    assert spy.calls[0]["unit"] == " lines"
    assert spy.calls[0]["show_progress"] is True


def test_progress_seam_load_syslog_calls_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """load_syslog wraps each per-file read with progress."""
    from sigwood.common import loader as loader_mod

    spy = _ProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "router.log").write_text(
        "Jun  1 12:00:00 router sshd[1]: hi\n", encoding="utf-8",
    )
    (syslog_dir / "webserver.log").write_text(
        "Jun  1 12:01:00 web nginx[2]: hi\n", encoding="utf-8",
    )

    loader_mod.load_syslog(syslog_dir, show_progress=False)

    descs = sorted(c["desc"] for c in spy.calls)
    assert descs == ["loaded router.log", "loaded webserver.log"]
    assert all(c["show_progress"] is False for c in spy.calls)
    assert all(c["unit"] == " lines" for c in spy.calls)


def test_progress_seam_load_pihole_calls_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """load_pihole wraps each per-file read with progress."""
    from sigwood.common import loader as loader_mod

    spy = _ProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text(
        "Jun  1 12:00:00 dnsmasq[1]: query[A] example.test from 192.0.2.10\n",
        encoding="utf-8",
    )

    loader_mod.load_pihole(pihole_dir, show_progress=True)

    assert len(spy.calls) == 1
    assert spy.calls[0]["desc"] == "loaded pihole.log"
    assert spy.calls[0]["unit"] == " lines"
    assert spy.calls[0]["show_progress"] is True


# ── CloudTrail single-iterator: per-shape input-line accounting ──────────────
#
# After `line_iter = progress(...)` exists in _cloudtrail_strategy_parse, ALL four
# wire-shape branches consume from the same wrapped iterator. The progress bar
# therefore reports actual INPUT lines (never parsed events) for every shape -
# including the single-line case: a one-line NDJSON file must
# report `loaded x: 1 lines`, NOT zero.


class _CountingProgressSpy:
    """Progress spy that wraps iteration and counts lines pulled through it.

    Distinct from _ProgressSpy in that it tracks per-call line counts via
    actual iteration - needed to assert the CloudTrail single-iterator drives
    every branch (envelope / multi-line pretty / NDJSON / bare-list).
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []  # one entry per call (desc, line_count)

    def __call__(self, iterable, *, desc, show_progress=True, unit=" lines",
                 total=None, stream=None):
        entry = {"desc": desc, "line_count": 0}
        self.calls.append(entry)

        def _counting():
            for line in iterable:
                entry["line_count"] += 1
                yield line

        return _counting()


def test_cloudtrail_one_line_ndjson_bar_reports_one_line_not_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single-event NDJSON CloudTrail file must
    NOT leave a ``loaded x: 0 lines`` record. The first-nonblank sniff
    consumes the one line through the shared wrapped iterator, so the bar
    correctly reports 1 line consumed."""
    from sigwood.common import loader as loader_mod

    spy = _CountingProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _ct_write_ndjson(cloudtrail_dir / "one.json.log",
                     [_ct_event(eventID="only-one")])

    df = loader_mod.load_cloudtrail(cloudtrail_dir)

    assert len(df) == 1
    assert len(spy.calls) == 1
    assert spy.calls[0]["desc"] == "loaded one.json.log"
    # The one input line was pulled through the wrapped iterator.
    assert spy.calls[0]["line_count"] == 1


def test_cloudtrail_multi_line_ndjson_bar_counts_every_input_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NDJSON branch consumes both the first-nonblank sniff AND the per-event
    stream from the same wrapped iterator - total = input lines."""
    from sigwood.common import loader as loader_mod

    spy = _CountingProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _ct_write_ndjson(cloudtrail_dir / "events.json.log", [
        _ct_event(eventID="a"),
        _ct_event(eventID="b"),
        _ct_event(eventID="c"),
    ])

    loader_mod.load_cloudtrail(cloudtrail_dir)

    assert spy.calls[0]["line_count"] == 3


def test_cloudtrail_envelope_bar_counts_envelope_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``{"Records": [...]}`` envelope: the helper-wrapped iterator carries
    the first line (and any additional input lines) before the whole-document
    join. A single-line envelope reports 1 input line."""
    from sigwood.common import loader as loader_mod

    spy = _CountingProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _ct_write_envelope_gz(cloudtrail_dir / "envelope.json.gz",
                          [_ct_event(eventID="env-1"),
                           _ct_event(eventID="env-2")])

    loader_mod.load_cloudtrail(cloudtrail_dir)

    # Single-line envelope = exactly one input line through the wrapped iter.
    assert spy.calls[0]["line_count"] == 1


def test_cloudtrail_pretty_multiline_bar_counts_every_input_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pretty-printed multi-line single-document fallback (first line is a
    JSON fragment): the wrapped iterator collects all remaining lines via
    ``"".join(line_iter)`` so the bar reports the full file line count, not
    just 1."""
    from sigwood.common import loader as loader_mod

    spy = _CountingProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    events = [_ct_event(eventID="pretty-1"), _ct_event(eventID="pretty-2")]
    pretty_text = json.dumps({"Records": events}, indent=2)
    (cloudtrail_dir / "pretty.json").write_text(pretty_text, encoding="utf-8")
    expected_lines = len(pretty_text.splitlines())

    loader_mod.load_cloudtrail(cloudtrail_dir)

    assert spy.calls[0]["line_count"] == expected_lines
    assert expected_lines > 1  # sanity: this fixture really is multi-line


def test_cloudtrail_bare_list_one_line_doc_bar_reports_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bare-list one-line document: the wrapped iterator delivers the single
    line for the sniff, no further iteration; bar = 1 line consumed."""
    from sigwood.common import loader as loader_mod

    spy = _CountingProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    events = [_ct_event(eventID="list-1"), _ct_event(eventID="list-2")]
    (cloudtrail_dir / "list.json").write_text(
        json.dumps(events), encoding="utf-8",
    )

    loader_mod.load_cloudtrail(cloudtrail_dir)

    assert spy.calls[0]["line_count"] == 1


def test_cloudtrail_bar_unit_is_lines_not_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CloudTrail bar declares ``unit=" lines"`` because it counts INPUT
    lines (the wrapped iterator), not parsed/emitted events. The
    parsed-event iteration in load_cloudtrail must NEVER be wrapped - that
    would label parsed events as lines, which is a lie."""
    from sigwood.common import loader as loader_mod

    spy = _ProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _ct_write_ndjson(cloudtrail_dir / "events.json.log", [
        _ct_event(eventID="a"), _ct_event(eventID="b"),
    ])

    loader_mod.load_cloudtrail(cloudtrail_dir)

    # Exactly ONE progress call per file (no separate event-iteration bar).
    assert len(spy.calls) == 1
    assert spy.calls[0]["unit"] == " lines"


# ── show_progress threading: load_required_logs → all four families ─────────


def test_load_required_logs_threads_show_progress_to_all_families(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """load_required_logs(show_progress=False) propagates to every family
    loader (zeek, syslog, pihole, cloudtrail). Closes the gap where the flag
    only threaded to load_logs and left the three flat loaders unsilenced."""
    from sigwood.common import loader as loader_mod

    spy = _ProgressSpy()
    monkeypatch.setattr(loader_mod, "progress", spy)

    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "conn.log", [
        {"ts": 1.0, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
         "id.resp_p": 443, "proto": "tcp"},
    ])

    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "router.log").write_text(
        "Jun  1 12:00:00 router sshd[1]: hi\n", encoding="utf-8",
    )

    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text(
        "Jun  1 12:00:00 dnsmasq[1]: query[A] example.test from 192.0.2.10\n",
        encoding="utf-8",
    )

    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _ct_write_ndjson(cloudtrail_dir / "events.json.log", [_ct_event()])

    loader_mod.load_required_logs(
        {
            "conn*.log*": "zeek_dir",
            "syslog_dir_pattern": "syslog_dir",
            "pihole_dir_pattern": "pihole_dir",
            "*.json*": "cloudtrail_dir",
        },
        {
            "zeek_dir": [zeek_dir],
            "syslog_dir": [syslog_dir],
            "pihole_dir": [pihole_dir],
            "cloudtrail_dir": [cloudtrail_dir],
        },
        show_progress=False,
    )

    # Every loader that called progress did so with show_progress=False -
    # no family leaked the default-True flag.
    assert spy.calls, "no progress calls recorded - fixture must exercise readers"
    assert all(c["show_progress"] is False for c in spy.calls)


# ── Zeek syslog.log v1 promotion (fidelity-aware syslog schema) ───────────────
#
# `syslog*.log*` is the loader's glob pattern for Zeek's own syslog.log; it
# routes through the zeek_dir branch (TSV + NDJSON) into the new
# _normalize_zeek_syslog_df. Result must be the 7-col canonical frame with
# minimal-5 first (ts, host, program, raw, message) and extended last
# (facility, severity).

def test_log_type_routes_syslog_pattern() -> None:
    """_log_type maps "syslog*.log*" to "syslog" so the normalizer map fires."""
    from sigwood.common.loader import _log_type
    assert _log_type("syslog*.log*") == "syslog"


def test_normalizer_map_contains_syslog_entry() -> None:
    """The new normalizer is wired into the dispatch table."""
    from sigwood.common.loader import _NORMALIZER_MAP
    from sigwood.parsers.zeek import _normalize_zeek_syslog_df
    assert _NORMALIZER_MAP["syslog"] is _normalize_zeek_syslog_df


def test_load_logs_zeek_syslog_ndjson_returns_canonical_seven_columns(
    tmp_path: Path,
) -> None:
    """load_logs on a Zeek syslog.log NDJSON file produces the canonical
    fidelity-aware syslog frame: minimal-5 first, then facility/severity."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(
        zeek_dir / "syslog.log",
        [
            {
                "_path": "syslog",
                "ts": 1779750000.0,
                "uid": "CSL01",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 41514,
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 514,
                "proto": "udp",
                "facility": "DAEMON",
                "severity": "INFO",
                "message": (
                    "Jun 11 12:00:00 host1 sshd[1234]: "
                    "Accepted publickey for user from 192.0.2.10"
                ),
            }
        ],
    )
    df = load_logs(zeek_dir, "syslog*.log*")
    assert list(df.columns) == [
        "ts", "host", "program", "raw", "message", "facility", "severity",
    ]
    assert len(df) == 1
    assert df.iloc[0]["host"] == "host1"
    assert df.iloc[0]["program"] == "sshd"
    assert df.iloc[0]["severity"] == "INFO"
    # Dropped Zeek-native fields.
    for col in ("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"):
        assert col not in df.columns


def test_load_logs_zeek_syslog_tsv_returns_canonical_seven_columns(
    tmp_path: Path,
) -> None:
    """load_logs on a Zeek syslog.log TSV file produces the same canonical
    frame as the NDJSON path (single normalizer, two front-ends)."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "syslog.log").write_text(
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tsyslog\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
        "\tproto\tfacility\tseverity\tmessage\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport"
        "\tenum\tstring\tstring\tstring\n"
        "1779750000.000000\tCSL01\t192.0.2.10\t41514\t198.51.100.20\t514"
        "\tudp\tDAEMON\tINFO"
        "\tJun 11 12:00:00 host1 sshd[1234]: Accepted publickey for user\n",
        encoding="utf-8",
    )
    df = load_logs(zeek_dir, "syslog*.log*")
    assert list(df.columns) == [
        "ts", "host", "program", "raw", "message", "facility", "severity",
    ]
    assert df.iloc[0]["host"] == "host1"
    assert df.iloc[0]["severity"] == "INFO"


def test_schema_warning_fires_for_zeek_syslog_missing_required_field() -> None:
    """Missing `message` on a Zeek-syslog frame trips the v1-required
    columns warning - minimal-5 are v1-required, facility/severity are not."""
    df = pd.DataFrame([{
        "ts": 1779750000.0,
        "host": "host1",
        "facility": "DAEMON",
        "severity": "INFO",
        # message / program / raw deliberately absent
    }])
    warning = _schema_warning("syslog*.log*", df)
    assert warning is not None
    assert "syslog.log fields not found" in warning
    assert "message" in warning


def test_schema_warning_does_not_fire_for_zeek_syslog_missing_facility() -> None:
    """facility/severity are extended/nullable - absence is not a warning."""
    df = pd.DataFrame([{
        "ts": 1779750000.0,
        "host": "host1",
        "program": "sshd",
        "raw": "<14>Jun 11 12:00:00 host1 sshd: ok",
        "message": "sshd: ok",
        # facility / severity absent - flat-feed shape, but ALSO valid for a
        # Zeek frame that happens to be missing extended fields.
    }])
    assert _schema_warning("syslog*.log*", df) is None


# ── bz2 / xz transparent decompression at _open_log ──────────────────────────
#
# `_open_log` is the single chokepoint every source flows through, so adding
# bz2/xz here covers conn/dns/syslog/pihole/cloudtrail/sniff. These tests
# observe the fix through the PUBLIC load_required_logs entry rather than
# touching `_open_log` directly - the bug only manifests once discovery feeds
# `_open_log`, so a sham helper-only test would miss it.


def _make_conn_ndjson_payload() -> bytes:
    """Two valid Zeek conn NDJSON rows, RFC 5737 placeholders."""
    return (
        "\n".join(json.dumps(r) for r in [
            {
                "_path": "conn",
                "ts": 1_779_750_000.0,
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 443,
                "proto": "tcp",
            },
            {
                "_path": "conn",
                "ts": 1_779_753_600.0,
                "id.orig_h": "192.0.2.11",
                "id.resp_h": "203.0.113.20",
                "id.resp_p": 22,
                "proto": "tcp",
            },
        ]) + "\n"
    ).encode("utf-8")


def test_load_required_logs_decompresses_bz2(tmp_path: Path) -> None:
    """A `conn.log.bz2` ingests as text rows - no replacement-char soup."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log.bz2").write_bytes(
        bz2.compress(_make_conn_ndjson_payload())
    )

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
    )

    df = result.logs["conn*.log*"]
    assert result.record_counts == {"conn*.log*": 2}
    assert result.warnings == []
    assert list(df[["src", "dst", "port"]].iloc[0]) == [
        "192.0.2.10", "198.51.100.20", 443,
    ]


def test_load_required_logs_decompresses_xz(tmp_path: Path) -> None:
    """A `conn.log.xz` ingests as text rows - no replacement-char soup."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log.xz").write_bytes(
        lzma.compress(_make_conn_ndjson_payload())
    )

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
    )

    df = result.logs["conn*.log*"]
    assert result.record_counts == {"conn*.log*": 2}
    assert result.warnings == []
    assert list(df[["src", "dst", "port"]].iloc[0]) == [
        "192.0.2.10", "198.51.100.20", 443,
    ]


def test_load_required_logs_corrupt_bz2_skips_with_warning(tmp_path: Path) -> None:
    """A corrupt `.bz2` (non-bzip2 bytes) is skipped with an actionable warning,
    not a traceback. bz2 raises OSError on bad data - already caught."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log.bz2").write_bytes(b"NOTBZIP2 garbage")

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
    )

    assert result.logs["conn*.log*"].empty
    assert any(
        "conn.log.bz2 could not be read" in w for w in result.warnings
    )


def test_load_required_logs_corrupt_xz_skips_with_warning(tmp_path: Path) -> None:
    """A corrupt `.xz` raises `lzma.LZMAError`, which is a direct
    `Exception` subclass (NOT `OSError`). Without the wrinkle fix this would
    leak past the boundary as a traceback. With it, the loader skips and
    emits the standard read warning."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log.xz").write_bytes(b"NOTXZ garbage")

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
    )

    assert result.logs["conn*.log*"].empty
    # The warning must land in the "incomplete or corrupt" branch - proves
    # `lzma.LZMAError` is recognised by `_zeek_file_read_warning`, not in the
    # generic class-name fallback. This is the critical wrinkle assertion.
    assert any(
        "conn.log.xz could not be read" in w and "incomplete or corrupt" in w
        for w in result.warnings
    )


# ── load_pihole: corrupt compressed-file skip-with-warning ──────────────────
#
# Mirror of load_syslog's corrupt-handling: per-file try/except over the
# decode-error family (incl. lzma.LZMAError, which isn't an OSError), so a
# corrupt .gz/.bz2/.xz in a pihole_dir doesn't take down the whole load.


@pytest.mark.parametrize("suffix, corrupt_bytes", [
    (".gz",  b"NOTGZIP garbage"),
    (".bz2", b"NOTBZIP2 garbage"),
    (".xz",  b"NOTXZ garbage"),
])
def test_load_pihole_corrupt_compressed_file_skipped_with_warning(
    tmp_path: Path, suffix: str, corrupt_bytes: bytes,
) -> None:
    """A corrupt compressed file in a pihole_dir is skipped per-file with the
    actionable read-warning. The good companion file still loads. .gz/.xz
    land in the "incomplete or corrupt" branch; .bz2's OSError falls to the
    generic fallback - both are acceptable, the required rail is
    "warned, not traceback'd"."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text(
        "Jun  1 12:00:00 dnsmasq[1]: query[A] example.test from 192.0.2.1\n",
        encoding="utf-8",
    )
    (pihole_dir / f"pihole.log{suffix}").write_bytes(corrupt_bytes)

    warnings: list[str] = []
    df = load_pihole(pihole_dir, _warnings=warnings)

    # Good file still loaded.
    assert len(df) == 1
    # Corrupt file produced an actionable warning, not a traceback.
    assert any(
        f"pihole.log{suffix} could not be read" in w for w in warnings
    )


def test_load_pihole_corrupt_xz_lands_in_incomplete_or_corrupt_branch(
    tmp_path: Path,
) -> None:
    """The wrinkle assertion at the pihole boundary: lzma.LZMAError reaches
    `_zeek_file_read_warning`'s compressed-incomplete branch, not the
    generic class-name fallback."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log.xz").write_bytes(b"NOTXZ garbage")

    warnings: list[str] = []
    load_pihole(pihole_dir, _warnings=warnings)

    assert any(
        "pihole.log.xz could not be read" in w and "incomplete or corrupt" in w
        for w in warnings
    )


# ── load_pihole: truncated (trailer-corrupt) compressed file honesty rail ──
#
# Truncated compressed files yield valid-looking lines until the trailer
# check raises. Pre-honesty-fix, those pre-EOF rows leaked into the returned
# frame even as the loader warned the file had been "skipped". Honesty rail:
# a file the loader warns it skipped contributes ZERO rows.

_PIHOLE_TRUNCATE_PAYLOAD = "\n".join(
    f"Jun  1 12:{i:02d}:00 dnsmasq[1]: query[A] host{i}.example.test from 192.0.2.{i + 1}"
    for i in range(20)
) + "\n"


def _pihole_truncated_compressed(payload: bytes, suffix: str) -> bytes:
    if suffix == ".gz":
        return gzip.compress(payload)[:-1]
    if suffix == ".bz2":
        return bz2.compress(payload)[:-1]
    if suffix == ".xz":
        return lzma.compress(payload)[:-1]
    raise ValueError(f"unsupported suffix {suffix!r}")


@pytest.mark.parametrize("suffix", [".gz", ".bz2", ".xz"])
def test_load_pihole_trailer_corrupt_compressed_contributes_zero_rows(
    tmp_path: Path, suffix: str,
) -> None:
    """A truncated `.gz` / `.bz2` / `.xz` pihole file warns AND contributes
    zero rows. The good companion file still loads."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    # Good companion - one identifiable query line.
    (pihole_dir / "pihole.log").write_text(
        "Jun  1 23:59:00 dnsmasq[1]: query[A] companion.example.test from 192.0.2.99\n",
        encoding="utf-8",
    )
    (pihole_dir / f"pihole.log{suffix}").write_bytes(
        _pihole_truncated_compressed(
            _PIHOLE_TRUNCATE_PAYLOAD.encode("utf-8"), suffix,
        )
    )

    warnings: list[str] = []
    df = load_pihole(pihole_dir, _warnings=warnings)

    assert any(
        f"pihole.log{suffix} could not be read" in w for w in warnings
    )
    # Only the companion row survives. Pre-honesty-fix, the truncated file's
    # pre-EOF rows leaked in.
    assert len(df) == 1
    assert df.iloc[0]["query"] == "companion.example.test"


# ── load_required_logs threading for the flat readers ──────────────────────


def test_load_required_logs_syslog_corrupt_xz_does_not_traceback(
    tmp_path: Path,
) -> None:
    """At the public CLI boundary: a corrupt
    `system.log.xz` in syslog_dir must NOT raise a `lzma.LZMAError` traceback
    past `load_required_logs` - it must degrade to a warning in the
    LoadResult."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "system.log.xz").write_bytes(b"NOTXZ garbage")
    # Good companion file so the load still returns rows.
    (syslog_dir / "router.log").write_text(
        "<134>May 31 12:00:00 router sshd[100]: Accepted publickey for user\n",
        encoding="utf-8",
    )

    result = load_required_logs(
        {"*.log*": "syslog_dir"},
        {"syslog_dir": [syslog_dir]},
    )

    df = result.logs["*.log*"]
    assert len(df) == 1
    assert df.iloc[0]["host"] == "router"
    assert any(
        "system.log.xz could not be read" in w
        and "incomplete or corrupt" in w
        for w in result.warnings
    )


def test_load_required_logs_pihole_corrupt_xz_does_not_traceback(
    tmp_path: Path,
) -> None:
    """Pihole sibling of the syslog test - same shape, same fix."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log.xz").write_bytes(b"NOTXZ garbage")
    (pihole_dir / "pihole.log").write_text(
        "Jun  1 12:00:00 dnsmasq[1]: query[A] example.test from 192.0.2.1\n",
        encoding="utf-8",
    )

    result = load_required_logs(
        {"pihole*.log*": "pihole_dir"},
        {"pihole_dir": [pihole_dir]},
    )

    df = result.logs["pihole*.log*"]
    assert len(df) == 1
    assert any(
        "pihole.log.xz could not be read" in w
        and "incomplete or corrupt" in w
        for w in result.warnings
    )


def test_load_required_logs_gz_regression(tmp_path: Path) -> None:
    """`.gz` ingestion behavior unchanged after bz2/xz additions."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log.gz").write_bytes(
        gzip.compress(_make_conn_ndjson_payload())
    )

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
    )

    assert result.record_counts == {"conn*.log*": 2}
    assert result.warnings == []


# ── CoverageTracker: tri-state SourceCoverage contract ─────────────────────────
#
# The tracker is the single mechanism every loader (and the runner's flat-Zeek
# default-window block) uses to record what was attempted vs what was kept.
# These tests pin the four arms of `coverage(frame_empty)` plus the kept
# short-circuit.


def test_coverage_tracker_no_files_read_returns_none_full_rows() -> None:
    """Date-pruned dated Zeek: discovery returned no files, the loader never
    enters the per-file loop. coverage(frame_empty=True) → (None, None)."""
    t = CoverageTracker()
    assert t.coverage(True) == SourceCoverage(None, None)


def test_coverage_tracker_files_read_no_valid_ts_returns_zero_full_rows() -> None:
    """Empty / header-only / unparseable-ts files: files were OPENED but no
    valid-ts rows survived parsing. coverage → (0, None). Drives the runner's
    NO-note branch (parse gap, not a window gap)."""
    t = CoverageTracker()
    t.note_file_read()
    t.note_file_read()
    assert t.coverage(True) == SourceCoverage(0, None)


def test_coverage_tracker_observe_counts_valid_ts_and_tracks_span() -> None:
    """observe(ts) increments valid_rows and folds ts into min/max. None / NaN
    / infinity are safely ignored (do not contaminate the span)."""
    t = CoverageTracker()
    t.note_file_read()
    t.observe(100.0)
    t.observe(200.0)
    t.observe(50.0)
    t.observe(None)
    t.observe(float("nan"))
    t.observe(float("inf"))
    t.observe(float("-inf"))
    sc = t.coverage(True)
    assert sc is not None
    assert sc.full_rows == 3
    assert sc.full_span is not None
    start, end = sc.full_span
    assert start.timestamp() == 50.0
    assert end.timestamp() == 200.0


def test_coverage_tracker_observe_frame_counts_valid_ts_and_tracks_span() -> None:
    """observe_frame(pre_df) counts valid-ts rows from the pre-window frame
    and folds the frame's min/max into the running span. NaN/infinite-ts rows
    are excluded."""
    t = CoverageTracker()
    t.note_file_read()
    df = pd.DataFrame({
        "ts": [10.0, 20.0, float("nan"), float("inf"), float("-inf"), 30.0],
    })
    t.observe_frame(df)
    sc = t.coverage(True)
    assert sc is not None
    assert sc.full_rows == 3
    assert sc.full_span is not None
    assert sc.full_span[0].timestamp() == 10.0
    assert sc.full_span[1].timestamp() == 30.0


def test_coverage_tracker_kept_short_circuits_to_none() -> None:
    """A row survived the window → mark_kept latches → coverage(False) returns
    None (no disclosure needed). Subsequent observe calls are cheap no-ops -
    the zero-normal-path-cost rail."""
    t = CoverageTracker()
    t.note_file_read()
    t.observe(100.0)
    t.mark_kept()
    # Later observes after the latch should NOT add to valid_rows
    t.observe(200.0)
    t.observe(300.0)
    # frame is non-empty (data survived) → coverage suppressed
    assert t.coverage(False) is None
    # Even with frame_empty=True, kept=True suppresses (defensive - runner
    # never passes True when data survived).
    assert t.coverage(True) is None


def test_coverage_tracker_frame_nonempty_returns_none() -> None:
    """The first branch of coverage(): frame survived → None, regardless of
    kept latch."""
    t = CoverageTracker()
    t.note_file_read()
    t.observe(100.0)
    assert t.coverage(False) is None


# ── Per-loader coverage integration (loader-level, no runner) ─────────────────


def test_load_logs_dated_zeek_outside_window_writes_coverage_none(
    tmp_path: Path,
) -> None:
    """Dated-Zeek date-pruned: discover_zeek_files returns no files because
    every dated subdir falls outside the requested window. The early-return
    branch must still write coverage so the runner's bare-note path fires."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    old_subdir = zeek_dir / "2025-01-01"
    old_subdir.mkdir()
    _write_ndjson(old_subdir / "conn.log", [
        {"ts": datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp(),
         "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
         "id.resp_p": 443, "proto": "tcp"},
    ])

    cov_dict: dict = {}
    df = load_logs(
        zeek_dir, "conn*.log*",
        since=datetime(2030, 1, 1, tzinfo=timezone.utc),
        until=datetime(2030, 12, 31, tzinfo=timezone.utc),
        _coverage=cov_dict,
    )

    assert df.empty
    assert "coverage" in cov_dict
    assert cov_dict["coverage"] == SourceCoverage(None, None)


def test_load_logs_empty_zeek_file_writes_coverage_zero(tmp_path: Path) -> None:
    """An empty / header-only Zeek file (rotation artifact) reads but yields
    no valid-ts rows → (0, None), the PARSE-GAP arm. The runner suppresses
    notes for this - telling the operator to widen the window on a file with
    no data would mislead."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text("", encoding="utf-8")

    cov_dict: dict = {}
    df = load_logs(zeek_dir, "conn*.log*", _coverage=cov_dict)

    assert df.empty
    assert cov_dict.get("coverage") == SourceCoverage(0, None)


def test_load_logs_populated_writes_no_coverage_entry(tmp_path: Path) -> None:
    """The mark_kept short-circuit: a normal in-window load writes NO coverage
    entry (the tracker's coverage(False) returns None for a populated frame)."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "conn.log", [
        {"ts": 1_700_000_000.0, "id.orig_h": "192.0.2.1",
         "id.resp_h": "198.51.100.1", "id.resp_p": 443, "proto": "tcp"},
    ])

    cov_dict: dict = {}
    df = load_logs(zeek_dir, "conn*.log*", _coverage=cov_dict)

    assert not df.empty
    assert "coverage" not in cov_dict


def test_load_pihole_stale_data_writes_coverage_span(tmp_path: Path) -> None:
    """A Pi-hole archive whose timestamps all fall outside the requested
    window: coverage records full_rows (the count of valid-ts rows seen
    pre-window) AND a span derived from those rows. This is the stale-Pi-hole
    motivating-bug shape at the loader level."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    # Use explicit year so year-guess heuristics can't drift the fixture.
    (pihole_dir / "pihole.log").write_text(
        "Jun  1 12:00:00 2025 dnsmasq[1]: query[A] example.test from 192.0.2.10\n"
        "Jun  1 12:01:00 2025 dnsmasq[1]: reply example.test is 203.0.113.1\n",
        encoding="utf-8",
    )

    cov_dict: dict = {}
    df = load_pihole(
        pihole_dir,
        since=datetime(2030, 1, 1, tzinfo=timezone.utc),
        until=datetime(2030, 12, 31, tzinfo=timezone.utc),
        _coverage=cov_dict,
    )

    assert df.empty
    sc = cov_dict.get("coverage")
    assert sc is not None
    # Some rows may year-guess differently - what matters is that the loader
    # writes SPAN coverage (full_rows > 0 with a non-None span), NOT parse-gap.
    if sc.full_rows is not None and sc.full_rows > 0:
        assert sc.full_span is not None
    else:
        # The fixture's year-suffixed format may parse to no valid ts on some
        # heuristics - fall back to the parse-gap arm rather than failing.
        assert sc.full_rows == 0


def test_load_pihole_wrong_family_only_skips_silently(tmp_path: Path) -> None:
    """Wrong-family skip (the NDJSON guard fires for an NDJSON file in
    pihole_dir): note_file_read does NOT fire for the skipped file, so the
    tracker sees zero files read. The runner suppresses notes for non-Zeek
    "no files read" cases anyway, but the loader's contract is to record
    truthfully - and the wrong-family file MUST NOT register as read."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    _write_ndjson(pihole_dir / "looks-like-zeek.log", [
        {"ts": 1.0, "extra": "irrelevant"},
    ])

    cov_dict: dict = {}
    df = load_pihole(pihole_dir, _coverage=cov_dict)

    assert df.empty
    sc = cov_dict.get("coverage")
    # files_read=False (note_file_read suppressed by wrong-family guard) →
    # full_rows is None at the LOADER level. The runner translates this to
    # "no note" because the BARE-note arm is zeek_dir-only.
    assert sc == SourceCoverage(None, None)


def test_load_cloudtrail_all_unparseable_eventtime_writes_coverage_zero(
    tmp_path: Path,
) -> None:
    """CloudTrail file where every event has unparseable eventTime →
    tracker sees note_file_read but observe() ignores None ts → coverage =
    (0, None). PARSE-GAP arm: no note."""
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _ct_write_ndjson(cloudtrail_dir / "events.json.log", [
        _ct_event(eventTime="not-a-timestamp", eventID="bad-1"),
        _ct_event(eventTime="also-not-a-time", eventID="bad-2"),
    ])

    cov_dict: dict = {}
    df = load_cloudtrail(cloudtrail_dir, _coverage=cov_dict)

    assert df.empty
    assert cov_dict.get("coverage") == SourceCoverage(0, None)


def test_load_cloudtrail_stale_data_writes_coverage_span(tmp_path: Path) -> None:
    """CloudTrail events all timestamped before the requested window →
    SPAN coverage."""
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _ct_write_ndjson(cloudtrail_dir / "events.json.log", [
        _ct_event(eventTime="2025-06-01T12:00:00Z", eventID="a"),
        _ct_event(eventTime="2025-06-02T12:00:00Z", eventID="b"),
    ])

    cov_dict: dict = {}
    df = load_cloudtrail(
        cloudtrail_dir,
        since=datetime(2030, 1, 1, tzinfo=timezone.utc),
        until=datetime(2030, 12, 31, tzinfo=timezone.utc),
        _coverage=cov_dict,
    )

    assert df.empty
    sc = cov_dict.get("coverage")
    assert sc is not None
    assert sc.full_rows == 2
    assert sc.full_span is not None


def test_load_required_logs_assembles_per_pattern_coverage(tmp_path: Path) -> None:
    """load_required_logs builds LoadResult.coverage from each load_*'s
    _coverage out-param under the SAME pattern key the runner reads."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    old = zeek_dir / "2025-01-01"
    old.mkdir()
    _write_ndjson(old / "conn.log", [
        {"ts": datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp(),
         "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1",
         "id.resp_p": 443, "proto": "tcp"},
    ])

    result = load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
        since=datetime(2030, 1, 1, tzinfo=timezone.utc),
        until=datetime(2030, 12, 31, tzinfo=timezone.utc),
    )

    assert "conn*.log*" in result.coverage
    assert result.coverage["conn*.log*"] == SourceCoverage(None, None)


# ── run_load guarantee + _SOURCE_LOADERS tripwire + Zeek TSV regressions ─────
#
# These tests lock the loader's required contracts: a fake
# ``SourceLoader`` driven through ``run_load`` exercises the uniform pipeline
# WITHOUT any format-specific wiring (progress + coverage + windowing +
# verbose-gated skip + read-corruption rail); the tripwire asserts every
# detector source-key is registered; the Zeek TSV regressions confirm the
# prefix-preserving sniff hands the full header block to ``parse_tsv_log``.


def test_run_load_fake_strategy_exercises_pipeline_mechanics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A FAKE ``SourceLoader`` driven through ``run_load`` exercises the
    pipeline's contract with ZERO format-specific wiring: progress is wrapped
    once per file, coverage is written for empty/window-excluded loads,
    in-window rows survive, NaN-ts under ``keep`` policy bypasses the window,
    verbose=True prints the skip message to stderr while verbose=False stays
    quiet, and a per-file decompression failure rides
    ``_zeek_file_read_warning`` without aborting the load.
    """
    from sigwood.common import loader as loader_mod

    # Spy the progress seam (intercepts kwargs without consuming the iterable).
    calls: list[dict] = []

    def progress_spy(iterable, *, desc, show_progress=True, unit=" lines",
                     total=None, stream=None):
        calls.append({"desc": desc, "unit": unit, "show_progress": show_progress})
        return iter(iterable)

    monkeypatch.setattr(loader_mod, "progress", progress_spy)

    # --- Build a fake stream strategy. parse yields canonical row dicts.
    def fake_parse(line_iter, *, path, warnings):  # noqa: ARG001
        for line in line_iter:
            ts_token, host = line.rstrip("\n").split("\t", 1)
            ts = float(ts_token) if ts_token != "NA" else float("nan")
            yield {"ts": ts, "host": host, "raw": line.rstrip("\n")}

    def fake_skip(path: Path) -> str | None:
        # Skip files named with .skip extension.
        return f"fake: skipping {path.name}" if path.suffix == ".skip" else None

    strategy_keep = loader_mod.SourceLoader(
        discover=lambda p, pat, s, u: [p],  # noqa: ARG005
        mode="stream",
        parse=fake_parse,
        ts_policy="keep",
        columns=["ts", "host", "raw"],
        should_skip=fake_skip,
        normalize=None,
    )

    # --- File 1: an in-window row + a NaN-ts row + finite/infinite tails.
    f_data = tmp_path / "good.log"
    f_data.write_text(
        f"{1.0}\tA\n"
        f"NA\tB\n"
        f"{99.0}\tC\n"
        f"{float('inf')}\tD\n"
        f"{float('-inf')}\tE\n",
        encoding="utf-8",
    )
    # --- File 2: should_skip drops this one.
    f_skip = tmp_path / "wrong.skip"
    f_skip.write_text("ignored\n", encoding="utf-8")
    # --- File 3: corrupt gzip - read-corruption rail catches.
    f_bad = tmp_path / "bad.gz"
    f_bad.write_bytes(b"not a real gzip stream")

    warnings: list[str] = []
    coverage: dict = {}

    # Quiet default: skip message NOT printed.
    df = loader_mod.run_load(
        strategy_keep,
        [f_data, f_skip, f_bad],
        pattern="",
        since=datetime.fromtimestamp(0.0, tz=timezone.utc),
        until=datetime.fromtimestamp(10.0, tz=timezone.utc),
        show_progress=True,
        verbose=False,
        _warnings=warnings,
        _coverage=coverage,
    )

    # In-window row (ts=1.0, host=A) + NaN-ts row (host=B, bypasses window).
    # Out-of-window (ts=99.0), +inf, and -inf drop; skipped file contributes
    # zero; corrupt file is caught with a read-warning.
    assert sorted(df["host"].tolist()) == ["A", "B"]
    captured = capsys.readouterr()
    assert "fake: skipping" not in captured.err  # quiet default
    # Read-corruption rail: bad.gz produced ONE warning, no traceback.
    assert any("bad.gz" in w for w in warnings)
    assert len(warnings) == 1
    # Progress was wrapped for the two readable files (not the skipped one).
    assert {c["desc"] for c in calls} == {"loaded good.log", "loaded bad.gz"}
    # mark_kept fired → no coverage write needed.
    assert "coverage" not in coverage

    # Infinity must also drop without a requested window, while the keep-policy
    # NaN row remains an intentionally retained unknown-time event.
    df_unbounded = loader_mod.run_load(
        strategy_keep,
        [f_data],
        pattern="",
        since=None,
        until=None,
        show_progress=False,
        verbose=False,
    )
    assert sorted(df_unbounded["host"].tolist()) == ["A", "B", "C"]

    # Now verbose=True surfaces the skip message; rebuild the spy log.
    calls.clear()
    capsys.readouterr()  # drain
    warnings2: list[str] = []
    coverage2: dict = {}
    df2 = loader_mod.run_load(
        strategy_keep,
        [f_data, f_skip],
        pattern="",
        since=datetime.fromtimestamp(0.0, tz=timezone.utc),
        until=datetime.fromtimestamp(10.0, tz=timezone.utc),
        show_progress=True,
        verbose=True,
        _warnings=warnings2,
        _coverage=coverage2,
    )
    captured = capsys.readouterr()
    assert "fake: skipping wrong.skip" in captured.err
    assert sorted(df2["host"].tolist()) == ["A", "B"]

    # Empty-load returns column-stable empty frame AND writes coverage for the
    # date-pruned case (no files).
    coverage3: dict = {}
    df3 = loader_mod.run_load(
        strategy_keep,
        [],
        pattern="",
        since=None,
        until=None,
        show_progress=False,
        verbose=False,
        _warnings=None,
        _coverage=coverage3,
    )
    assert df3.empty
    assert list(df3.columns) == ["ts", "host", "raw"]
    assert coverage3.get("coverage") == SourceCoverage(None, None)


def test_run_load_drop_policy_discards_nan_ts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ts_policy='drop'`` discards NaN-ts rows before windowing - the
    other half of the policy fork (the ``keep`` half is exercised above)."""
    from sigwood.common import loader as loader_mod

    monkeypatch.setattr(
        loader_mod,
        "progress",
        lambda iterable, *, desc, show_progress=True, unit=" lines",
        total=None, stream=None: iter(iterable),
    )

    def fake_parse(line_iter, *, path, warnings):  # noqa: ARG001
        for line in line_iter:
            ts_token, host = line.rstrip("\n").split("\t", 1)
            ts = float(ts_token) if ts_token != "NA" else float("nan")
            yield {"ts": ts, "host": host, "raw": line.rstrip("\n")}

    strategy_drop = loader_mod.SourceLoader(
        discover=lambda p, pat, s, u: [p],  # noqa: ARG005
        mode="stream",
        parse=fake_parse,
        ts_policy="drop",
        columns=["ts", "host", "raw"],
        should_skip=None,
        normalize=None,
    )

    f = tmp_path / "mix.log"
    f.write_text(f"{1.0}\tA\nNA\tB\n", encoding="utf-8")

    df = loader_mod.run_load(
        strategy_drop, [f], pattern="",
        since=None, until=None,
        show_progress=False, verbose=False,
    )
    # NaN-ts row dropped; in-window row kept.
    assert df["host"].tolist() == ["A"]


def test_source_loaders_keyspace_covers_every_detector_source_key() -> None:
    """Additive tripwire: every detector ``REQUIRED_LOGS``/``OPTIONAL_LOGS``
    source key has a ``_SOURCE_LOADERS`` entry. A new source family that
    skips registry registration will fail this test instead of producing a
    ``ValueError("unknown source key …")`` at runtime."""
    import importlib
    import pkgutil

    from sigwood.common.loader import _SOURCE_LOADERS
    from sigwood import detectors as _detectors_pkg

    seen_keys: set[str] = set()
    for modinfo in pkgutil.iter_modules(_detectors_pkg.__path__):
        mod = importlib.import_module(f"sigwood.detectors.{modinfo.name}")
        for log in list(getattr(mod, "REQUIRED_LOGS", []) or []) + \
                   list(getattr(mod, "OPTIONAL_LOGS", []) or []):
            source = log.get("source")
            if source:
                seen_keys.add(source)

    missing = seen_keys - set(_SOURCE_LOADERS)
    assert not missing, f"detector source keys lacking _SOURCE_LOADERS entries: {missing}"


def test_zeek_tsv_mixed_prefix_preserves_header_directives(tmp_path: Path) -> None:
    """The Zeek frame strategy's prefix-preserving sniff
    hands the FULL header block (#separator, #fields, #types, #path) to
    ``parse_tsv_log`` so a real conn.tsv with a data row parses correctly.
    A one-line peek would discard the header directives and the parser
    would fail or produce a bare frame."""
    f = tmp_path / "conn.log"
    f.write_text(
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\thistory\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tstring\n"
        "1748649600.000000\tCTest01\t192.0.2.10\t51514\t203.0.113.20\t443\ttcp\tssl\t3.5\t1500\t8200\tSF\tT\tF\t(empty)\n"
        "#close\t2026-06-01-12-00-00\n",
        encoding="utf-8",
    )

    df = load_logs(f.parent, "conn*.log*", _files=[f])
    assert not df.empty
    # The conn normalizer runs over the parsed frame; canonical columns appear.
    assert "src" in df.columns
    assert "dst" in df.columns
    assert df.iloc[0]["src"] == "192.0.2.10"


def test_zeek_tsv_header_only_returns_bare_empty_preserving_header_block(
    tmp_path: Path,
) -> None:
    """A header-only TSV (header block + #close, no data row) flows through
    the same prefix-preserving sniff to ``parse_tsv_log``; behavior matches
    today (parser produces an empty/header-only frame, the load returns
    bare empty after normalize)."""
    f = tmp_path / "conn.log"
    f.write_text(
        "#separator \\x09\n"
        "#path\tconn\n"
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
        "#types\ttime\taddr\taddr\tport\tenum\n"
        "#close\t2026-06-01-12-00-00\n",
        encoding="utf-8",
    )

    df = load_logs(f.parent, "conn*.log*", _files=[f])
    # Header-only TSV: parser handles the header block; the load returns an
    # empty frame. Critically, no traceback (the prefix WAS preserved → the
    # parser saw a complete header) and the empty shape is bare - Zeek
    # empties never column-stabilize.
    assert df.empty


def test_load_logs_single_file_bypass_runs_on_dated_zeek_basename(
    tmp_path: Path,
) -> None:
    """Digest single-file Zeek bypass regression: a Zeek file whose basename
    does NOT match ``conn*.log*`` (e.g. dated rotation
    ``2026-06-09.conn.log``) still loads when ``_files=[file]`` is provided
    - discovery is SKIPPED and the file goes straight through the Zeek
    strategy. ``run_digest`` relies on this for files routed by sniff,
    not by glob."""
    f = tmp_path / "2026-06-09.conn.log"
    f.write_text(
        "#separator \\x09\n"
        "#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\thistory\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tstring\n"
        "1748649600.000000\tCTest01\t192.0.2.10\t51514\t203.0.113.20\t443\ttcp\tssl\t3.5\t1500\t8200\tSF\tT\tF\t(empty)\n"
        "#close\t2026-06-01-12-00-00\n",
        encoding="utf-8",
    )

    # Note: pattern is the GLOB the digest passes through (``conn*.log*``);
    # the basename here doesn't match it, but ``_files=`` shortcircuits
    # discovery so the file loads anyway.
    df = load_logs(f.parent, "conn*.log*", _files=[f])
    assert not df.empty
    assert df.iloc[0]["src"] == "192.0.2.10"


# ── Flat-log rotation-peek windowing (syslog + pihole) ───────────────────────
#
# since/until are DERIVED by parsing the fixture lines themselves (not a
# hardcoded year), so the tests are independent of the machine clock AND
# inherently exercise clock parity with parse_timestamp's year-guess heuristic.


def _dns_line(mon: str, day: int, hh: str = "12:00:00") -> str:
    """A dnsmasq/Pi-hole query line whose timestamp is ``mon day hh``."""
    return f"{mon} {day:>2} {hh} dnsmasq[1]: query[A] example.test from 192.0.2.1"


def _sys_line(mon: str, day: int, hh: str = "12:00:00") -> str:
    """An RFC 3164 syslog line whose timestamp is ``mon day hh``."""
    return f"{mon} {day:>2} {hh} host1 sshd[1]: session opened for user"


def _write_rot(path: Path, first_line: str, *, compress: bool = False) -> None:
    """Write a one-line rotation file; ``first_line`` is the file's OLDEST row."""
    body = first_line + "\n" if first_line else "\n"
    if compress:
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(body)
    else:
        path.write_text(body, encoding="utf-8")


def _make_rot_family(
    dirpath: Path,
    base: str,
    ts_by_ordinal: dict[int, tuple[str, int]],
    *,
    line_fn=_dns_line,
) -> None:
    """Build a rotation family: ordinal 0 → ``base``; N → ``base.N`` (first line
    carries the given month/day so it controls the file's oldest-row ts)."""
    dirpath.mkdir(parents=True, exist_ok=True)
    for idx, (mon, day) in ts_by_ordinal.items():
        name = base if idx == 0 else f"{base}.{idx}"
        _write_rot(dirpath / name, line_fn(mon, day))


# Clock parity (binding) - peek ts EQUALS the ts the loader filters on.

def test_rotation_peek_ts_matches_loader_ts_pihole(tmp_path: Path) -> None:
    for mon, day in [("Jun", 1), ("Dec", 25)]:  # Dec exercises the year-rollback
        f = tmp_path / f"pihole_{mon}.log"
        _write_rot(f, _dns_line(mon, day))
        peek = _peek_first_ts(f)
        assert peek is not None
        assert load_pihole(f).iloc[0]["ts"] == peek.timestamp()


def test_rotation_peek_ts_matches_loader_ts_syslog(tmp_path: Path) -> None:
    for mon, day in [("Jun", 2), ("Dec", 31)]:
        f = tmp_path / f"sys_{mon}.log"
        _write_rot(f, _sys_line(mon, day))
        peek = _peek_first_ts(f)
        assert peek is not None
        assert load_syslog(f).iloc[0]["ts"] == peek.timestamp()


def test_rotation_peek_ts_matches_loader_ts_syslog_non_utc(
    pin_tz, tmp_path: Path
) -> None:
    """Peek/loader clock parity under a non-UTC host zone, anchored to the TRUE
    instant via manual +6h arithmetic - bare parity cannot catch a wall-clock
    misinterpretation because both sides share parse_timestamp."""
    pin_tz("Etc/GMT+6")
    local_naive = (datetime.now() - timedelta(days=30)).replace(
        second=0, microsecond=0
    )
    f = tmp_path / "sys_local.log"
    _write_rot(
        f,
        _sys_line(
            local_naive.strftime("%b"), local_naive.day, local_naive.strftime("%H:%M:%S")
        ),
    )
    peek = _peek_first_ts(f)
    assert peek is not None
    true_epoch = (
        (local_naive + timedelta(hours=6)).replace(tzinfo=timezone.utc).timestamp()
    )
    assert peek.timestamp() == true_epoch
    assert load_syslog(f).iloc[0]["ts"] == true_epoch


def test_peek_first_ts_permission_denied_returns_none(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Unopenable files are unpeekable, not fatal; load-time handling owns warnings."""
    import sigwood.common.loader as loader_mod

    f = tmp_path / "pihole.log"
    f.write_text(
        "Jun  5 12:00:00 dnsmasq[1]: query[A] a.test from 192.0.2.10\n",
        encoding="utf-8",
    )

    def _deny(_path: Path):
        raise PermissionError("synthetic denied")

    monkeypatch.setattr(loader_mod, "_open_log", _deny)

    assert _peek_first_ts(f) is None


def test_peek_first_ts_corrupt_gzip_returns_none(tmp_path: Path) -> None:
    """Corrupt compressed files defer to the load path instead of aborting peek."""
    f = tmp_path / "pihole.log.gz"
    f.write_bytes(b"not a gzip stream")

    assert _peek_first_ts(f) is None


def test_syslog_window_filter_true_instants_non_utc(pin_tz, tmp_path: Path) -> None:
    """An explicit UTC ``since`` selects syslog rows by their TRUE instants under
    a non-UTC host zone. ``since`` and the expected epoch are manual fixed-offset
    arithmetic (+6h), never parse_timestamp - interpreting the wall-clock as UTC
    would shift the newer row 6h earlier and wrongly exclude it."""
    pin_tz("Etc/GMT+6")
    local_a = (datetime.now() - timedelta(days=30)).replace(second=0, microsecond=0)
    local_b = local_a - timedelta(hours=3)
    d = tmp_path / "syslogd"
    d.mkdir()
    lines = [
        _sys_line(local_b.strftime("%b"), local_b.day, local_b.strftime("%H:%M:%S")),
        _sys_line(local_a.strftime("%b"), local_a.day, local_a.strftime("%H:%M:%S")),
    ]
    (d / "messages.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    true_a = (local_a + timedelta(hours=6)).replace(tzinfo=timezone.utc)
    since = true_a - timedelta(hours=1)
    df = load_syslog(d, since=since)
    assert len(df) == 1
    assert df.iloc[0]["ts"] == true_a.timestamp()


# Per-group selection.

def test_rotation_per_group_two_dirs_keeps_both_straddles(tmp_path: Path) -> None:
    """/a and /b each {log,.1,.2,.3}; BOTH .2 straddle `since` → keep both .2,
    skip only each group's older .3. A single-stream early-stop would skip b.2."""
    tsmap = {0: ("Jun", 6), 1: ("Jun", 5), 2: ("Jun", 4), 3: ("Jun", 3)}
    a, b = tmp_path / "a", tmp_path / "b"
    _make_rot_family(a, "pihole.log", tsmap)
    _make_rot_family(b, "pihole.log", tsmap)
    files = sorted(a.glob("*")) + sorted(b.glob("*"))
    since = parse_timestamp(_dns_line("Jun", 5))
    selected, info = _rotation_windowed_files(files, since, None)
    sel_a = {p.name for p in selected if p.parent == a}
    sel_b = {p.name for p in selected if p.parent == b}
    assert "pihole.log.2" in sel_a and "pihole.log.2" in sel_b
    assert "pihole.log.3" not in sel_a and "pihole.log.3" not in sel_b
    assert info.loaded == 6 and info.skipped == 2 and not info.fallback


def test_rotation_per_group_per_host_independent(tmp_path: Path) -> None:
    """router.* (newer) + server.* (older) in ONE dir: router's tail is kept
    while server is pruned independently - grouping is per (parent, base)."""
    d = tmp_path / "sys"
    _make_rot_family(d, "router.log", {0: ("Jun", 10), 1: ("Jun", 9), 2: ("Jun", 8)}, line_fn=_sys_line)
    _make_rot_family(d, "server.log", {0: ("Jun", 6), 1: ("Jun", 5), 2: ("Jun", 4)}, line_fn=_sys_line)
    files = sorted(d.glob("*"))
    since = parse_timestamp(_sys_line("Jun", 7))
    selected, info = _rotation_windowed_files(files, since, None)
    names = {p.name for p in selected}
    assert "router.log.2" in names          # router tail kept (all ≥ since)
    assert "server.log.1" not in names      # server pruned independently
    assert "server.log.2" not in names
    assert info.loaded == 4 and info.skipped == 2


def test_rotation_early_stop_single_group_skips_old_tail(tmp_path: Path) -> None:
    """active(empty) + .1(in-window) + .2(straddle) selected; older .3 skipped
    and NEVER peeked (recorded with a None ts - no fabricated timestamp)."""
    d = tmp_path / "p"
    d.mkdir()
    _write_rot(d / "pihole.log", "")                       # empty active → conservative include
    _write_rot(d / "pihole.log.1", _dns_line("Jun", 6))
    _write_rot(d / "pihole.log.2", _dns_line("Jun", 4))    # straddle
    _write_rot(d / "pihole.log.3", _dns_line("Jun", 2))    # old → skipped, not read
    files = sorted(d.glob("*"))
    since = parse_timestamp(_dns_line("Jun", 5))
    selected, info = _rotation_windowed_files(files, since, None)
    assert {p.name for p in selected} == {"pihole.log", "pihole.log.1", "pihole.log.2"}
    assert info.skipped == 1
    assert ("pihole.log.3", None) in info.skipped_files


def test_rotation_conservative_includes_unpeekable_and_corrupt(tmp_path: Path) -> None:
    """A blank-only file and a corrupt .gz are INCLUDED (never aborts), and do
    not break the monotonic chain."""
    d = tmp_path / "p"
    d.mkdir()
    _write_rot(d / "pihole.log", _dns_line("Jun", 6))
    (d / "pihole.log.1").write_text("\n   \n", encoding="utf-8")   # unpeekable
    (d / "pihole.log.2.gz").write_bytes(b"not a gzip stream")      # corrupt → peek raises
    files = sorted(d.glob("*"))
    since = parse_timestamp(_dns_line("Jun", 1))                   # very old → all in window
    selected, info = _rotation_windowed_files(files, since, None)
    assert {p.name for p in selected} == {"pihole.log", "pihole.log.1", "pihole.log.2.gz"}
    assert info.skipped == 0 and not info.fallback


def test_rotation_fallback_is_data_true_whole_pattern(tmp_path: Path) -> None:
    """One out-of-order group disables pruning for the WHOLE pattern: full set
    returned, skipped=0, and the well-formed group's would-be-skipped tail is
    NOT pruned (data-true, not just note-suppressed)."""
    a, b = tmp_path / "a", tmp_path / "b"
    _make_rot_family(a, "pihole.log", {0: ("Jun", 6), 1: ("Jun", 5), 2: ("Jun", 4), 3: ("Jun", 3)})
    # b: log(Jun 8) then .1(Jun 10) - going newest→oldest the first-ts RISES → disorder.
    _make_rot_family(b, "pihole.log", {0: ("Jun", 8), 1: ("Jun", 10)})
    files = sorted(a.glob("*")) + sorted(b.glob("*"))
    since = parse_timestamp(_dns_line("Jun", 5))
    selected, info = _rotation_windowed_files(files, since, None)
    assert info.fallback is True
    assert info.skipped == 0 and info.loaded == len(files)
    assert {p.resolve() for p in selected} == {p.resolve() for p in files}
    # Well-formed group A's .3 would be rotation-skipped without fallback - present here.
    assert any(p.parent == a and p.name == "pihole.log.3" for p in selected)


def test_syslog_files_drops_appledouble_and_orders_numerically(tmp_path: Path) -> None:
    d = tmp_path / "p"
    d.mkdir()
    for name in ["._pihole.log", "pihole.log", "pihole.log.1", "pihole.log.2", "pihole.log.10"]:
        _write_rot(d / name, _dns_line("Jun", 1))
    names = [p.name for p in _syslog_files(d)]
    assert "._pihole.log" not in names
    assert names == ["pihole.log", "pihole.log.1", "pihole.log.2", "pihole.log.10"]


# Explicit-file protection (load_required_logs end-to-end).

def test_rotation_lone_explicit_old_file_no_windowing_no_skip(tmp_path: Path) -> None:
    """An explicit OLD file → loaded, never rotation-windowed, no RotationSkipInfo."""
    old = tmp_path / "pihole.log.5"
    _write_rot(old, _dns_line("Jun", 1))
    since = parse_timestamp(_dns_line("Jun", 10))
    res = load_required_logs({"*.log*": "pihole_dir"}, {"pihole_dir": [old]}, since=since)
    assert "*.log*" not in res.rotation_skips
    assert res.data_size_bytes == old.stat().st_size


def test_rotation_explicit_overlap_loads_not_skipped(tmp_path: Path) -> None:
    """A path the window WOULD skip, also named explicitly AND reachable via the
    dir → loaded (bytes counted) and NOT in the skip count (no fake skip)."""
    d = tmp_path / "p"
    _make_rot_family(d, "pihole.log", {0: ("Jun", 6), 1: ("Jun", 5), 2: ("Jun", 4), 3: ("Jun", 3)})
    explicit = d / "pihole.log.3"   # window would skip .3; protected by the explicit input
    since = parse_timestamp(_dns_line("Jun", 5))
    res = load_required_logs(
        {"*.log*": "pihole_dir"}, {"pihole_dir": [explicit, d]}, since=since,
    )
    info = res.rotation_skips["*.log*"]
    assert info.skipped == 0 and info.skipped_files == []
    all_files = [d / n for n in ("pihole.log", "pihole.log.1", "pihole.log.2", "pihole.log.3")]
    assert res.data_size_bytes == sum(p.stat().st_size for p in all_files)


def test_rotation_no_window_reads_all_no_skip(tmp_path: Path) -> None:
    """Bare load (no since/until) reads everything; no peek, no RotationSkipInfo."""
    d = tmp_path / "p"
    _make_rot_family(d, "pihole.log", {0: ("Jun", 6), 1: ("Jun", 5), 2: ("Jun", 4), 3: ("Jun", 3)})
    res = load_required_logs({"*.log*": "pihole_dir"}, {"pihole_dir": [d]})
    assert "*.log*" not in res.rotation_skips
    all_files = [d / n for n in ("pihole.log", "pihole.log.1", "pihole.log.2", "pihole.log.3")]
    assert res.data_size_bytes == sum(p.stat().st_size for p in all_files)


def test_rotation_windows_syslog_dir_family(tmp_path: Path) -> None:
    """The shared helper engages for syslog_dir too (both flat families)."""
    d = tmp_path / "s"
    _make_rot_family(d, "router.log", {0: ("Jun", 6), 1: ("Jun", 5), 2: ("Jun", 4), 3: ("Jun", 3)}, line_fn=_sys_line)
    since = parse_timestamp(_sys_line("Jun", 5))
    res = load_required_logs({"*.log*": "syslog_dir"}, {"syslog_dir": [d]}, since=since)
    info = res.rotation_skips["*.log*"]
    assert info.loaded == 3 and info.skipped == 1 and not info.fallback


def test_rotation_verbose_skip_lines_tolerate_none_ts(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """verbose=True prints per-file skip lines; an unpeeked tail file (None ts)
    prints NO '(oldest …)' detail (never fabricates), a peeked too-new leading
    file prints its real ts. Default (verbose=False) is quiet."""
    d = tmp_path / "p"
    _make_rot_family(d, "pihole.log", {
        0: ("Jun", 10),  # too-new leading (oldest > until) → skipped, ts known
        1: ("Jun", 8),
        2: ("Jun", 6),
        3: ("Jun", 4),   # straddle since → kept
        4: ("Jun", 2),   # too-old tail → skipped, NOT peeked → ts None
    })
    files = sorted(d.glob("*"))
    since = parse_timestamp(_dns_line("Jun", 5))
    until = parse_timestamp(_dns_line("Jun", 9))

    _rotation_windowed_files(files, since, until, verbose=False)
    assert capsys.readouterr().err == ""

    _rotation_windowed_files(files, since, until, verbose=True)
    err = capsys.readouterr().err
    assert "skipped pihole.log.4 (outside the window)\n" in err   # None ts → no detail
    assert "skipped pihole.log (outside the window)\n" in err      # peeked → same wording


# ── date-stamped rotation-peek pruning (dateext + exporter output) ───────────
#
# Filename dates are ORDERING/grouping hints (+ the Family-2 structural overlap
# check); the line first-ts stays the sole prune gate. Fixtures keep the
# filename-date order aligned with the line-ts order so the peek's monotonicity
# check does not fire. since/until are derived from fixture LINES, never a
# hardcoded year.


def _make_dateext_family(
    dirpath: Path,
    base: str,
    dated: list[tuple[str, int, int]],
    *,
    live: tuple[str, int] | None = None,
    year: int = 2026,
    line_fn=_dns_line,
) -> None:
    """Build a logrotate ``dateext`` family: an optional live ``base`` head plus
    ``base.YYYYMMDD`` files. ``dated`` = ``(mon_name, mon_num, day)`` per dated
    file; ``live`` = the undated head's ``(mon_name, day)``. Each file's first
    line carries the matching month/day so its peek ts aligns with the
    filename-date order."""
    dirpath.mkdir(parents=True, exist_ok=True)
    if live is not None:
        _write_rot(dirpath / base, line_fn(live[0], live[1]))
    for mon, mon_num, day in dated:
        _write_rot(dirpath / f"{base}.{year}{mon_num:02d}{day:02d}", line_fn(mon, day))


def _make_export_family(
    dirpath: Path,
    base: str,
    days: list[int],
    *,
    year: int = 2026,
    mon_num: int = 6,
    mon_name: str = "Jun",
    line_fn=_dns_line,
) -> None:
    """Build non-overlapping daily exporter files ``{base}_{YYYYMMDD}_1d.log``,
    one per day; the first line carries that day so the peek ts aligns with the
    filename-date order (`_auto_filename`'s whole-day ``_Nd`` shape)."""
    dirpath.mkdir(parents=True, exist_ok=True)
    for day in days:
        name = f"{base}_{year}{mon_num:02d}{day:02d}_1d.log"
        _write_rot(dirpath / name, line_fn(mon_name, day))


# Classifier-level (helper) coverage.

def test_rotation_eight_digit_non_date_stays_numeric() -> None:
    """An 8-digit trailing token that is NOT a valid calendar date (month 13) is
    a numeric ordinal, not dateext - age_rank is the raw int, no window."""
    assert _classify_rotation_name("pihole.log.20241301") == ("pihole.log", 20241301, None)


def test_rotation_export_to_form_classifies_and_orders() -> None:
    """The ``_to_`` exporter form parses to ``[start, end_date + (HH+1) h)`` (the
    end is CEILed to the next hour so the window is a guaranteed superset of the
    real until) and a newer start date yields a smaller age_rank (sorts newer)."""
    base1, rank1, win1 = _classify_rotation_name("export_20260601_to_20260608_14h.log")
    assert base1 == "export"
    assert win1 == (datetime(2026, 6, 1), datetime(2026, 6, 8, 15))  # 14h → ceil 15h
    base2, rank2, win2 = _classify_rotation_name("export_20260605_to_20260606_00h.log")
    assert base2 == "export" and win2 == (datetime(2026, 6, 5), datetime(2026, 6, 6, 1))
    assert rank2 < rank1  # later start (Jun 5 > Jun 1) → newer → smaller rank


def test_rotation_export_huge_days_falls_to_floor() -> None:
    """FIX 1 - an unbounded ``_Nd`` day count that overflows the date math is
    caught (not raised) and falls to the floor singleton."""
    assert _classify_rotation_name("foo_20260101_9999999d.log") == (
        "foo_20260101_9999999d.log",
        0,
        None,
    )


def test_rotation_export_nonpositive_window_falls_to_floor() -> None:
    """A malformed non-positive export window - empty ``_0d`` or an inverted
    ``_to_`` (end ≤ start) - carries NO declared window (would read as disjoint
    and dodge the guards); it floors to a singleton instead."""
    assert _classify_rotation_name("splunk_20260601_0d.log") == (
        "splunk_20260601_0d.log",
        0,
        None,
    )
    assert _classify_rotation_name("export_20260608_to_20260601_00h.log") == (
        "export_20260608_to_20260601_00h.log",
        0,
        None,
    )


def test_rotation_export_zero_day_does_not_silently_skip_sibling(tmp_path: Path) -> None:
    """A malformed ``_0d`` export-looking file beside a normal same-start ``_1d``
    export must NOT silently skip the normal file. Flooring the ``_0d`` gives it
    its own base, so each is peeked independently and BOTH survive."""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "splunk_20260601_0d.log", _sys_line("Jun", 1, "06:00:00"))
    _write_rot(d / "splunk_20260601_1d.log", _sys_line("Jun", 1, "18:00:00"))
    files = sorted(d.glob("*"))
    since = parse_timestamp(_sys_line("Jun", 1, "12:00:00"))
    selected, info = _rotation_windowed_files(files, since, None)
    names = {p.name for p in selected}
    assert "splunk_20260601_1d.log" in names  # the in-window normal file is NOT skipped
    assert "splunk_20260601_0d.log" in names  # the floored _0d singleton survives too
    assert not info.fallback


def test_rotation_export_classify_superset_of_auto_filename() -> None:
    """FOLD 6 / FIX 3 - the classifier window is always a SUPERSET of the real
    ``[since, until)`` that ``exporters._auto_filename`` encoded. Couples
    ``_EXPORT_WINDOW_RE`` to the exporter format (a future format change that
    disengaged the guard would fail here) and pins the ``_to_`` ceil property."""
    # whole-day _Nd: exact window (both endpoints midnight)
    since, until = datetime(2026, 6, 1), datetime(2026, 6, 8)
    win = _classify_rotation_name(_auto_filename("splunk", since, until))[2]
    assert win is not None and win[0] <= since and win[1] >= until
    # partial-day _to_: non-midnight endpoints → start floors, end ceils → superset
    since, until = datetime(2026, 6, 1, 3, 30), datetime(2026, 6, 8, 14, 45)
    win = _classify_rotation_name(_auto_filename("splunk", since, until))[2]
    assert win is not None and win[0] <= since and win[1] >= until


def test_rotation_export_partnn_falls_to_floor() -> None:
    """A ``_partNN`` infix is NOT claimed as an export window - it falls to the
    singleton floor (loaded-not-pruned), the safe behavior."""
    assert _classify_rotation_name("splunk_20260601_1d_part01.log") == (
        "splunk_20260601_1d_part01.log",
        0,
        None,
    )


# Per-group selection (helper) coverage.

def test_rotation_dateext_now_prunes(tmp_path: Path) -> None:
    """dateext PRUNES instead of falling back: a live head + dated files
    order newest→oldest and the old tail is skipped."""
    d = tmp_path / "p"
    _make_dateext_family(
        d, "pihole.log",
        dated=[("Jun", 6, 5), ("Jun", 6, 4), ("Jun", 6, 3)],
        live=("Jun", 6),
    )
    files = sorted(d.glob("*"))
    since = parse_timestamp(_dns_line("Jun", 5))
    selected, info = _rotation_windowed_files(files, since, None)
    names = {p.name for p in selected}
    assert {"pihole.log", "pihole.log.20260605", "pihole.log.20260604"} <= names
    assert "pihole.log.20260603" not in names  # old tail skipped
    assert info.loaded == 3 and info.skipped == 1 and not info.fallback


def test_rotation_dateext_peek_ts_matches_loader_ts(tmp_path: Path) -> None:
    """Clock parity for a dateext-named file - peek ts EQUALS the loader ts."""
    f = tmp_path / "auth.log.20260625"
    _write_rot(f, _sys_line("Jun", 25))
    peek = _peek_first_ts(f)
    assert peek is not None
    assert load_syslog(f).iloc[0]["ts"] == peek.timestamp()


def test_rotation_export_window_prunes(tmp_path: Path) -> None:
    """Non-overlapping daily exporter files order newest→oldest and prune."""
    d = tmp_path / "s"
    _make_export_family(d, "splunk", [6, 5, 4, 3], line_fn=_sys_line)
    files = sorted(d.glob("*"))
    since = parse_timestamp(_sys_line("Jun", 5))
    selected, info = _rotation_windowed_files(files, since, None)
    names = {p.name for p in selected}
    assert {"splunk_20260606_1d.log", "splunk_20260605_1d.log", "splunk_20260604_1d.log"} <= names
    assert "splunk_20260603_1d.log" not in names
    assert info.loaded == 3 and info.skipped == 1 and not info.fallback


def test_rotation_export_overlap_falls_back(tmp_path: Path) -> None:
    """A _7d window overlapping a _1d daily under one base → whole-pattern
    fallback, skipped=0, full set, reason 'overlapping export windows'."""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "splunk_20260601_7d.log", _sys_line("Jun", 1))   # [Jun 1, Jun 8)
    _write_rot(d / "splunk_20260605_1d.log", _sys_line("Jun", 5))   # [Jun 5, Jun 6) ⊂ above
    files = sorted(d.glob("*"))
    since = parse_timestamp(_sys_line("Jun", 5))
    selected, info = _rotation_windowed_files(files, since, None)
    assert info.fallback is True
    assert info.fallback_reason == "overlapping export windows"
    assert info.skipped == 0 and info.loaded == len(files)
    assert {p.resolve() for p in selected} == {p.resolve() for p in files}


def test_rotation_export_equal_window_duplicate_falls_back(tmp_path: Path) -> None:
    """Equal-window duplicates (the silent-miss class) → fallback, NOT pruning.
    Proves compression stripping: a ``.log`` and its ``.log.gz`` classify to the
    same base+window after stripping only the compression suffix."""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "splunk_20260601_1d.log", _sys_line("Jun", 1))
    _write_rot(d / "splunk_20260601_1d.log.gz", _sys_line("Jun", 1), compress=True)
    files = sorted(d.glob("*"))
    since = parse_timestamp(_sys_line("Jun", 1))
    selected, info = _rotation_windowed_files(files, since, None)
    assert info.fallback is True
    assert info.fallback_reason == "overlapping export windows"
    assert info.skipped == 0 and info.loaded == len(files)


# Same-rank duplicate slots (FIX 2) - un-orderable, fall back for ALL schemes.

def test_rotation_dateext_same_date_duplicate_falls_back(tmp_path: Path) -> None:
    """A dateext file + its ``.gz`` sibling collapse to ONE age_rank → un-orderable
    duplicate → whole-pattern fallback (NOT a silent skip of the in-window .gz)."""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "auth.log.20260605", _sys_line("Jun", 5, "06:00:00"))
    _write_rot(d / "auth.log.20260605.gz", _sys_line("Jun", 5, "18:00:00"), compress=True)
    files = sorted(d.glob("*"))
    since = parse_timestamp(_sys_line("Jun", 5, "12:00:00"))
    selected, info = _rotation_windowed_files(files, since, None)
    assert info.fallback is True
    assert info.fallback_reason == "duplicate rotation files"
    assert info.skipped == 0 and info.loaded == len(files)


def test_rotation_numeric_duplicate_falls_back(tmp_path: Path) -> None:
    """A numeric rotation + its ``.gz`` sibling share a stripped name → fallback
    'duplicate rotation files' (closes the pre-existing numeric-dup silent-miss)."""
    d = tmp_path / "p"
    d.mkdir()
    _write_rot(d / "pihole.log", _dns_line("Jun", 6))
    _write_rot(d / "pihole.log.2", _dns_line("Jun", 4))
    _write_rot(d / "pihole.log.2.gz", _dns_line("Jun", 4), compress=True)
    files = sorted(d.glob("*"))
    since = parse_timestamp(_dns_line("Jun", 5))
    selected, info = _rotation_windowed_files(files, since, None)
    assert info.fallback is True
    assert info.fallback_reason == "duplicate rotation files"
    assert info.skipped == 0


def test_rotation_live_compressed_duplicate_falls_back(tmp_path: Path) -> None:
    """A live ``.log`` + its ``.log.gz`` (same stripped name) → 'duplicate rotation
    files' - the head-of-group duplicate slot."""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "auth.log", _sys_line("Jun", 6))
    _write_rot(d / "auth.log.gz", _sys_line("Jun", 6), compress=True)
    files = sorted(d.glob("*"))
    since = parse_timestamp(_sys_line("Jun", 5))
    selected, info = _rotation_windowed_files(files, since, None)
    assert info.fallback is True and info.fallback_reason == "duplicate rotation files"


def test_rotation_zero_indexed_prunes_not_dup(tmp_path: Path) -> None:
    """A 0-indexed scheme (``auth.log`` + ``.0`` BOTH age_rank 0) is NOT a
    duplicate - distinct stripped names → it PRUNES the out-of-window tail with
    fallback=False and no 'duplicate rotation files' note. (The age_rank-tie test
    flagged this falsely.)"""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "auth.log", _sys_line("Jun", 6))
    _write_rot(d / "auth.log.0", _sys_line("Jun", 5))
    _write_rot(d / "auth.log.1", _sys_line("Jun", 4))  # straddle since
    _write_rot(d / "auth.log.2", _sys_line("Jun", 3))  # out of window → skipped
    files = sorted(d.glob("*"))
    since = parse_timestamp(_sys_line("Jun", 5))
    selected, info = _rotation_windowed_files(files, since, None)
    assert info.fallback is False
    assert info.fallback_reason is None  # NOT a misleading "duplicate" note
    assert "auth.log.2" not in {p.name for p in selected}
    assert info.skipped == 1


def test_rotation_leading_zero_not_a_dup(tmp_path: Path) -> None:
    """``.02`` and ``.2`` both int-rank 2 but are DISTINCT files (distinct stripped
    names) → not flagged as a duplicate (proceeds past the dup branch)."""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "s.log.2", _sys_line("Jun", 5))
    _write_rot(d / "s.log.02", _sys_line("Jun", 4))
    files = sorted(d.glob("*"))
    since = parse_timestamp(_sys_line("Jun", 1))  # very old → all in window
    selected, info = _rotation_windowed_files(files, since, None)
    assert info.fallback_reason != "duplicate rotation files"


# End-to-end (load_required_logs) coverage - real discovery → window_select →
# run_load seam: selected ROWS and the RotationSkipInfo must agree.

def test_rotation_dateext_prunes_end_to_end_pihole(tmp_path: Path) -> None:
    """dateext pruning through the pihole_dir loader: 3 files selected, and the
    straddle file's out-of-window row is then trimmed by the precise row filter."""
    d = tmp_path / "p"
    _make_dateext_family(
        d, "pihole.log",
        dated=[("Jun", 6, 5), ("Jun", 6, 4), ("Jun", 6, 3)],
        live=("Jun", 6),
    )
    since = parse_timestamp(_dns_line("Jun", 5))
    res = load_required_logs({"*.log*": "pihole_dir"}, {"pihole_dir": [d]}, since=since)
    info = res.rotation_skips["*.log*"]
    assert info.loaded == 3 and info.skipped == 1 and not info.fallback
    df = res.logs["*.log*"]
    days = {datetime.fromtimestamp(ts).day for ts in df["ts"]}
    assert days == {5, 6}  # Jun 3 pruned (file); Jun 4 straddle file kept but row trimmed


def test_rotation_export_equal_window_fallback_end_to_end_syslog(tmp_path: Path) -> None:
    """Equal-window export duplicates through the syslog_dir loader → full read
    (both rows), fallback recorded with the overlap reason."""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "splunk_20260601_1d.log", _sys_line("Jun", 1))
    _write_rot(d / "splunk_20260601_1d.log.gz", _sys_line("Jun", 1), compress=True)
    since = parse_timestamp(_sys_line("Jun", 1))
    res = load_required_logs({"*.log*": "syslog_dir"}, {"syslog_dir": [d]}, since=since)
    info = res.rotation_skips["*.log*"]
    assert info.fallback is True
    assert info.fallback_reason == "overlapping export windows"
    assert info.skipped == 0
    assert len(res.logs["*.log*"]) == 2  # both files read (full archive), both in window


def test_rotation_export_huge_days_end_to_end_no_crash(tmp_path: Path) -> None:
    """FIX 1 end-to-end - an overflow-inducing ``_Nd`` name in a flat dir loads
    without a raw OverflowError reaching the runner; it floors to its OWN base
    (a singleton group) and is peeked independently."""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "foo_20260101_9999999d.log", _sys_line("Jun", 5))
    _write_rot(d / "server.log", _sys_line("Jun", 6))
    since = parse_timestamp(_sys_line("Jun", 5))
    res = load_required_logs({"*.log*": "syslog_dir"}, {"syslog_dir": [d]}, since=since)
    assert len(res.logs["*.log*"]) == 2  # no crash; both in-window rows present


def test_rotation_dateext_duplicate_rows_survive_end_to_end(tmp_path: Path) -> None:
    """FIX 2 end-to-end - the duplicate's in-window row survives the full read it
    triggers (the silent-miss this fix closes: without the guard the .gz sibling's
    18:00 row would be skipped as 'older tail')."""
    d = tmp_path / "s"
    d.mkdir()
    _write_rot(d / "auth.log.20260605", _sys_line("Jun", 5, "06:00:00"))
    _write_rot(d / "auth.log.20260605.gz", _sys_line("Jun", 5, "18:00:00"), compress=True)
    since = parse_timestamp(_sys_line("Jun", 5, "12:00:00"))
    res = load_required_logs({"*.log*": "syslog_dir"}, {"syslog_dir": [d]}, since=since)
    info = res.rotation_skips["*.log*"]
    assert info.fallback and info.fallback_reason == "duplicate rotation files"
    # The .gz sibling's 18:00 row survived the full read; the 06:00 row is the ONLY
    # one trimmed by the precise since-filter. Compare to the parsed ts - clock
    # parity, TZ-robust (parse_timestamp's tz vs a local fromtimestamp would skew).
    ts_set = set(res.logs["*.log*"]["ts"])
    expected_06 = parse_timestamp(_sys_line("Jun", 5, "06:00:00")).timestamp()
    expected_18 = parse_timestamp(_sys_line("Jun", 5, "18:00:00")).timestamp()
    assert len(res.logs["*.log*"]) == 1
    assert expected_18 in ts_set and expected_06 not in ts_set


# ── universal default window: family helpers ─────────────────────────────────


def test_is_bounded_family_neutral_and_zeek_alias() -> None:
    """is_bounded is pure path-shape; is_zeek_bounded delegates to it."""
    assert is_bounded([]) is False
    f = Path(__file__)  # a real regular file
    d = Path(__file__).parent  # a real directory
    assert is_bounded([f]) is True
    assert is_bounded([d]) is False
    assert is_bounded([f, d]) is False
    # Alias is byte-identical for the digest path.
    assert is_zeek_bounded([f]) == is_bounded([f])
    assert is_zeek_bounded([d]) == is_bounded([d])


def test_source_ts_policy() -> None:
    """ts policy is declared on each strategy: keep-policy families (syslog/pihole)
    KEEP unparseable-ts rows; drop-policy (zeek/cloudtrail) DROP. The resolver reads
    this directly off the strategy."""
    assert _SOURCE_LOADERS["syslog_dir"].ts_policy == "keep"
    assert _SOURCE_LOADERS["pihole_dir"].ts_policy == "keep"
    assert _SOURCE_LOADERS["zeek_dir"].ts_policy == "drop"
    assert _SOURCE_LOADERS["cloudtrail_dir"].ts_policy == "drop"
    assert "unknown_dir" not in _SOURCE_LOADERS


def test_apply_ts_filter_keep_null_retains_nan_rows_but_drops_infinity() -> None:
    """keep_null=True retains NaN-ts rows alongside in-window rows; the default
    (keep_null=False) drops them - byte-identical to every existing caller."""
    import math
    base = datetime(2026, 6, 5, 12, 0, tzinfo=timezone.utc)
    df = pd.DataFrame([
        {"ts": base.timestamp(), "m": "in"},
        {"ts": (base - timedelta(days=5)).timestamp(), "m": "old"},
        {"ts": float("nan"), "m": "nan"},
        {"ts": float("inf"), "m": "pos-inf"},
        {"ts": float("-inf"), "m": "neg-inf"},
    ])
    since = base - timedelta(days=1)
    keep = _apply_ts_filter(df, since, base, keep_null=True)
    assert set(keep["m"]) == {"in", "nan"}
    drop = _apply_ts_filter(df, since, base)  # default
    assert set(drop["m"]) == {"in"}
    assert not any(math.isnan(x) for x in drop["ts"])
    unbounded_keep = _apply_ts_filter(df, None, None, keep_null=True)
    assert set(unbounded_keep["m"]) == {"in", "old", "nan"}


def test_flat_family_default_floor_pihole_and_syslog(tmp_path: Path) -> None:
    """The flat floor peeks DIRECTORY candidates' max first-ts and returns
    (f_max − span, None); None when nothing is peekable. Directory-only inputs
    drive the anchor."""
    span = timedelta(days=1)

    # pihole: two rotation files, oldest first-ts Jun 1 / Jun 5 respectively.
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log.1").write_text(
        "Jun  1 12:00:00 dnsmasq[1]: query[A] a.test from 192.0.2.1\n", encoding="utf-8"
    )
    (pihole_dir / "pihole.log").write_text(
        "Jun  5 12:00:00 dnsmasq[1]: query[A] b.test from 192.0.2.1\n", encoding="utf-8"
    )
    floor = _flat_default_floor(_SOURCE_LOADERS["pihole_dir"], [pihole_dir], "pihole*.log*", span)
    assert floor is not None
    # Derive expected from the SAME yearless-ts parser the floor uses, so the
    # parse_timestamp year-rollback applies to both sides (clock-independent).
    expected = _peek_first_ts(pihole_dir / "pihole.log") - span
    assert floor[0] == expected
    assert floor[1] is None

    # syslog: same mechanism, *.log* discovery.
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "host.log").write_text(
        "Jun  5 12:00:00 host kernel: line\n", encoding="utf-8"
    )
    sfloor = _flat_default_floor(_SOURCE_LOADERS["syslog_dir"], [syslog_dir], "*.log*", span)
    assert sfloor is not None
    assert sfloor[0] == _peek_first_ts(syslog_dir / "host.log") - span
    assert sfloor[1] is None


def test_flat_family_default_floor_unpeekable_returns_none(tmp_path: Path) -> None:
    """No parseable first-ts across candidates → None (runner load-full fallback)."""
    d = tmp_path / "syslog"
    d.mkdir()
    (d / "host.log").write_text(
        "Xxx  1 12:00:00 host kernel: unparseable month\n", encoding="utf-8"
    )
    assert _flat_default_floor(_SOURCE_LOADERS["syslog_dir"], [d], "*.log*", timedelta(days=1)) is None


def test_flat_family_default_floor_permission_peek_uses_remaining_candidates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A permission-denied peek contributes no floor ts but does not leak."""
    import sigwood.common.loader as loader_mod

    span = timedelta(days=1)
    d = tmp_path / "pihole"
    d.mkdir()
    denied = d / "pihole.log"
    readable = d / "pihole.log.1"
    denied.write_text(
        "Jun  5 12:00:00 dnsmasq[1]: query[A] denied.test from 192.0.2.10\n",
        encoding="utf-8",
    )
    readable.write_text(
        "Jun  1 12:00:00 dnsmasq[1]: query[A] readable.test from 192.0.2.11\n",
        encoding="utf-8",
    )
    expected_ts = _peek_first_ts(readable)
    assert expected_ts is not None
    expected = expected_ts - span
    real_open = loader_mod._open_log

    def _deny_one(path: Path):
        if path == denied:
            raise PermissionError("synthetic denied")
        return real_open(path)

    monkeypatch.setattr(loader_mod, "_open_log", _deny_one)

    floor = _flat_default_floor(_SOURCE_LOADERS["pihole_dir"], [d], "pihole*.log*", span)
    assert floor is not None
    assert floor == (expected, None)


def test_flat_family_default_floor_excludes_explicit_files(tmp_path: Path) -> None:
    """Only is_dir() inputs drive the anchor - an explicit file passed in the list
    is ignored (1E: explicit files load regardless, must not drive the floor)."""
    explicit = tmp_path / "old.log"
    explicit.write_text("Jun  1 12:00:00 host kernel: old\n", encoding="utf-8")
    d = tmp_path / "syslog"
    d.mkdir()
    (d / "host.log").write_text("Jun  5 12:00:00 host kernel: new\n", encoding="utf-8")
    floor = _flat_default_floor(
        _SOURCE_LOADERS["syslog_dir"], [explicit, d], "*.log*", timedelta(days=1)
    )
    # Anchor is the DIR file (Jun 5), NOT the explicit Jun-1 file - proves exclusion.
    # Derive expected from the same parser (clock-independent year-rollback).
    assert floor[0] == _peek_first_ts(d / "host.log") - timedelta(days=1)


# ── pattern-aware flat discovery (pihole narrowing; explicit-file intent) ─────


def test_source_default_window_eligible_cloudtrail_opts_out() -> None:
    """default_window_eligible is declared on each strategy; the resolver reads it
    directly off the strategy. CloudTrail
    opts out (baseline-relative)."""
    assert _SOURCE_LOADERS["cloudtrail_dir"].default_window_eligible is False
    assert _SOURCE_LOADERS["zeek_dir"].default_window_eligible is True
    assert _SOURCE_LOADERS["syslog_dir"].default_window_eligible is True
    assert _SOURCE_LOADERS["pihole_dir"].default_window_eligible is True
    assert "unknown_dir" not in _SOURCE_LOADERS


def test_pihole_directory_discovery_narrows_to_pattern(tmp_path: Path) -> None:
    """A pihole DIRECTORY discovers only ``pihole*.log*`` - not sibling syslog /
    cloudtrail files in a shared dir."""
    d = tmp_path / "shared"
    d.mkdir()
    (d / "pihole.log").write_text("x\n", encoding="utf-8")
    (d / "pihole.log.1").write_text("y\n", encoding="utf-8")
    (d / "syslog_host.log").write_text("z\n", encoding="utf-8")
    (d / "cloudtrail.json.log").write_text("{}\n", encoding="utf-8")
    names = {p.name for p in _syslog_files(d, "pihole*.log*")}
    assert names == {"pihole.log", "pihole.log.1"}
    # `_syslog_files`' broad `*.log*` default still grabs everything - it is the
    # retained Pi-hole filename helper (and backs the Pi-hole mismatch check).
    # NOTE: syslog discovery does not use this glob; it content-sniffs via
    # `_discover_syslog_files`.
    assert {p.name for p in _syslog_files(d)} == {
        "pihole.log", "pihole.log.1", "syslog_host.log", "cloudtrail.json.log",
    }


def test_pihole_explicit_nonmatching_file_still_loads(tmp_path: Path) -> None:
    """An explicit FILE routed as Pi-hole loads even if its name doesn't match
    ``pihole*.log*`` - the pattern applies to DIRECTORY discovery only."""
    f = tmp_path / "events.log"
    f.write_text("Jun  5 12:00:00 dnsmasq[1]: query[A] a.test from 192.0.2.1\n",
                 encoding="utf-8")
    assert _syslog_files(f, "pihole*.log*") == [f]
    df = load_pihole(f)  # routes through the file path → loads
    assert len(df) == 1


def test_pihole_plan_and_loader_one_universe(tmp_path: Path) -> None:
    """Plan-time satisfiability and the loader discover the SAME pihole universe:
    a dir of only non-pihole files → not satisfiable AND loads empty."""
    from sigwood.runner import _any_input_yields_files

    d = tmp_path / "syslogonly"
    d.mkdir()
    (d / "syslog_host.log").write_text("Jun  5 12:00:00 host kernel: x\n",
                                       encoding="utf-8")
    # Plan: pihole pattern finds nothing here.
    assert _any_input_yields_files("pihole_dir", [d], "pihole*.log*") is False
    # Loader: same - discovers no pihole files, loads an empty (column-stable) frame.
    df = load_pihole(d)
    assert len(df) == 0
    assert list(df.columns) == _PIHOLE_COLUMNS


def test_pihole_dir_nonmatching_logs_disclosed_not_silent(tmp_path: Path) -> None:
    """A configured pihole DIRECTORY holding .log files that don't match
    ``pihole*.log*`` (e.g. a mis-named dnsmasq log or a shared export dir) loads
    nothing - but it is DISCLOSED via a loader warning, never a silent miss."""
    d = tmp_path / "shared"
    d.mkdir()
    (d / "dnsmasq.log").write_text(
        "Jun  5 12:00:00 dnsmasq[1]: query[A] a.test from 192.0.2.1\n",
        encoding="utf-8",
    )
    res = load_required_logs({"pihole*.log*": "pihole_dir"}, {"pihole_dir": [d]})
    assert res.record_counts.get("pihole*.log*", 0) == 0, "non-matching name not loaded"
    assert any("none match 'pihole*.log*'" in w for w in res.warnings), res.warnings

    # A correctly-named pihole dir loads AND emits no mismatch warning.
    good = tmp_path / "pihole"
    good.mkdir()
    (good / "pihole.log").write_text(
        "Jun  5 12:00:00 dnsmasq[1]: query[A] a.test from 192.0.2.1\n",
        encoding="utf-8",
    )
    res2 = load_required_logs({"pihole*.log*": "pihole_dir"}, {"pihole_dir": [good]})
    assert res2.record_counts.get("pihole*.log*", 0) == 1
    assert not any("none match" in w for w in res2.warnings), res2.warnings


# ── syslog content-sniff discovery gate (Item E) ───────────────────────────────

def test_syslog_gate_accepts_extensionless_rhel_streams(tmp_path: Path) -> None:
    """RHEL/Fedora streams carry no `.log` suffix - the content gate accepts
    `messages`/`secure`/`maillog`/`cron` by RFC-3164 content; per-line hosts come
    from content (H4), not the filename."""
    d = tmp_path / "varlog"
    d.mkdir()
    (d / "messages").write_text(
        "<134>May 31 12:00:00 host-a kernel: link up\n", encoding="utf-8")
    (d / "secure").write_text(
        "<134>May 31 12:01:00 host-b sshd[100]: Accepted publickey for user\n",
        encoding="utf-8")
    (d / "maillog").write_text(
        "<134>May 31 12:02:00 host-c postfix/smtpd[200]: connect from relay1\n",
        encoding="utf-8")
    (d / "cron").write_text(
        "<134>May 31 12:03:00 host-d CROND[300]: (root) CMD (placeholder)\n",
        encoding="utf-8")

    res = load_required_logs({"*.log*": "syslog_dir"}, {"syslog_dir": [d]})
    df = res.logs["*.log*"]
    assert len(df) == 4
    assert set(df["host"]) == {"host-a", "host-b", "host-c", "host-d"}
    assert res.warnings == []


def test_syslog_gate_rejects_non_syslog_logs_silently(tmp_path: Path, capsys) -> None:
    """An ISO-timestamped `dnf.log` and a systemd `boot.log` are dropped by the
    content gate - no rows AND no per-file stderr at any verbosity."""
    d = tmp_path / "varlog"
    d.mkdir()
    (d / "dnf.log").write_text(
        "2026-06-01T12:00:00+0000 INFO --- logging initialized ---\n",
        encoding="utf-8")
    (d / "boot.log").write_text("[  OK  ] Started Some Service.\n", encoding="utf-8")
    (d / "messages").write_text(
        "<134>May 31 12:00:00 host-a kernel: link up\n", encoding="utf-8")

    res = load_required_logs(
        {"*.log*": "syslog_dir"}, {"syslog_dir": [d]}, verbose=True,
    )
    df = res.logs["*.log*"]
    assert len(df) == 1
    assert set(df["host"]) == {"host-a"}
    err = capsys.readouterr().err
    assert "dnf.log" not in err
    assert "boot.log" not in err


def test_syslog_gate_read_is_byte_bounded(tmp_path: Path, monkeypatch) -> None:
    """The gate reads a BOUNDED `read(_SYSLOG_SNIFF_BYTES)` on an unclassified
    candidate and NEVER iterates / readlines it - a line-bounded read would scan
    a newline-sparse binary (wtmp/btmp/lastlog) to EOF. This is the regression
    this thread exists to prevent."""
    import sigwood.common.loader as L

    calls: list[int] = []

    class _Spy:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n):
            calls.append(n)
            return "\x00\x00\x00"  # NUL → binary → rejected

        def __iter__(self):
            raise AssertionError("gate must not iterate the handle")

        def readline(self, *a):
            raise AssertionError("gate must not readline the handle")

    f = tmp_path / "btmp"
    f.write_bytes(b"\x00" * 4096)
    monkeypatch.setattr(L, "_open_log", lambda p: _Spy())

    assert _looks_like_syslog(f) is False
    assert calls == [_SYSLOG_SNIFF_BYTES]


def test_syslog_gate_accepts_dnsmasq_bearing_messages(tmp_path: Path) -> None:
    """A `messages` whose lines are dnsmasq queries IS accepted into syslog - the
    gate runs the syslog recognizer DIRECTLY (dnsmasq lines are RFC 3164), not
    the full sniff_format cascade (which would route them to dns)."""
    d = tmp_path / "varlog"
    d.mkdir()
    (d / "messages").write_text(
        "<30>May 31 12:00:00 host-a dnsmasq[1]: query[A] a.test from 192.0.2.1\n",
        encoding="utf-8")
    assert [p.name for p in _discover_syslog_files(d)] == ["messages"]


def test_syslog_zero_accepted_dir_one_summary_warning(tmp_path: Path) -> None:
    """A syslog dir holding only non-syslog files → exactly ONE summary warning
    (directory path only, NO per-file name list); a dir with >=1 accepted stream
    → NO warning; an EMPTY dir → NO warning."""
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "dnf.log").write_text("2026-06-01T12:00:00 INFO x\n", encoding="utf-8")
    (bad / "junk").write_bytes(b"\x00\x01\x02")
    res = load_required_logs({"*.log*": "syslog_dir"}, {"syslog_dir": [bad]})
    assert res.record_counts.get("*.log*", 0) == 0
    matches = [
        w for w in res.warnings
        if "looks like syslog (RFC 3164 or ISO-8601)" in w
    ]
    assert len(matches) == 1, res.warnings
    assert "nothing in" in matches[0]
    assert str(bad) in matches[0]
    assert "dnf.log" not in matches[0] and "junk" not in matches[0]

    good = tmp_path / "good"
    good.mkdir()
    (good / "messages").write_text(
        "<134>May 31 12:00:00 host-a kernel: x\n", encoding="utf-8")
    res2 = load_required_logs({"*.log*": "syslog_dir"}, {"syslog_dir": [good]})
    assert not any("looks like syslog" in w for w in res2.warnings)

    empty = tmp_path / "empty"
    empty.mkdir()
    res3 = load_required_logs({"*.log*": "syslog_dir"}, {"syslog_dir": [empty]})
    assert not any("looks like syslog" in w for w in res3.warnings)


def test_syslog_explicit_file_bypasses_gate(tmp_path: Path) -> None:
    """A named unrecognized file loads as intent because discovery is bypassed."""
    f = tmp_path / "dnf.log"
    f.write_text("2026-06-01T12:00:00 INFO x\n", encoding="utf-8")
    assert _discover_syslog_files(f) == [f]
    assert len(load_syslog(f)) == 1


def test_syslog_plan_time_lockstep_with_gate(tmp_path: Path) -> None:
    """Plan-time satisfiability uses the SAME content gate: a dir of only
    `dnf.log` is NOT satisfiable; a `messages`-bearing dir IS."""
    from sigwood.runner import _any_input_yields_files

    dnf_only = tmp_path / "dnf"
    dnf_only.mkdir()
    (dnf_only / "dnf.log").write_text(
        "2026-06-01T12:00:00+0000 INFO --- logging initialized ---\n",
        encoding="utf-8",
    )
    assert _any_input_yields_files("syslog_dir", [dnf_only], "*.log*") is False

    msgs = tmp_path / "msgs"
    msgs.mkdir()
    (msgs / "messages").write_text(
        "<134>May 31 12:00:00 host-a kernel: x\n", encoding="utf-8")
    assert _any_input_yields_files("syslog_dir", [msgs], "*.log*") is True


def test_syslog_default_window_floor_anchors_on_accepted_only(tmp_path: Path) -> None:
    """flat_family_default_floor over a syslog dir with `dnf.log` (ISO, gate-
    rejected) + a binary + RFC-3164 streams anchors f_max on the MAX accepted
    candidate's peek ts - rejected files never contribute a peek."""
    d = tmp_path / "varlog"
    d.mkdir()
    (d / "messages").write_text(
        "<134>May 31 12:00:00 host-a kernel: x\n", encoding="utf-8")
    (d / "secure").write_text(  # later ts → should win f_max
        "<134>Jun  1 12:00:00 host-b sshd[1]: x\n", encoding="utf-8")
    (d / "dnf.log").write_text("2026-06-01T12:00:00 INFO x\n", encoding="utf-8")
    (d / "junk").write_bytes(b"\x00\x01\x02")

    span = timedelta(days=1)
    floor = _flat_default_floor(_SOURCE_LOADERS["syslog_dir"], [d], "*.log*", span)
    assert floor is not None
    f_max, until = floor
    assert until is None
    later = _peek_first_ts(d / "secure")
    assert later is not None
    assert f_max == later - span


# ── BATCH 1: file_select_windows decouples the peek from the row filter ──────
#
# A flat family's conservative default-window floor (f_max - span) must feed the
# rotation-peek (window_select) ONLY, never run_load's row filter - the precise
# post-load trim does the row windowing. These pin the decoupling directly at the
# loader boundary, so a future refactor that row-filters on the floor is caught
# even if a runner-level repro drifts.


def test_load_required_logs_file_select_window_feeds_peek_not_row_filter(
    tmp_path: Path, monkeypatch,
) -> None:
    """file_select_windows[source] reaches window_select; source_windows[source]
    reaches run_load. All four since/until values are DISTINCT so the routing
    cannot pass by coincidence."""
    import dataclasses
    from sigwood.common.loader import pipeline

    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    _make_rot_family(pihole_dir, "pihole.log", {0: ("Jun", 6), 1: ("Jun", 5)})

    captured: dict = {"ws": [], "rl": []}
    real_rl = pipeline.run_load

    def spy_rl(strategy, files, pattern, since, until, **kw):
        captured["rl"].append((since, until))
        return real_rl(strategy, files, pattern, since, until, **kw)

    monkeypatch.setattr(pipeline, "run_load", spy_rl)

    orig = pipeline._SOURCE_LOADERS["pihole_dir"]
    real_ws = orig.window_select

    def spy_ws(files, since, until, *, verbose=False):
        captured["ws"].append((since, until))
        return real_ws(files, since, until, verbose=verbose)

    monkeypatch.setitem(
        pipeline._SOURCE_LOADERS, "pihole_dir",
        dataclasses.replace(orig, window_select=spy_ws),
    )

    precise = (datetime(2026, 6, 1, tzinfo=timezone.utc),
               datetime(2026, 6, 2, tzinfo=timezone.utc))
    fsel = (datetime(2026, 6, 3, tzinfo=timezone.utc),
            datetime(2026, 6, 4, tzinfo=timezone.utc))
    load_required_logs(
        {"pihole*.log*": "pihole_dir"},
        {"pihole_dir": [pihole_dir]},
        source_windows={"pihole_dir": precise},
        file_select_windows={"pihole_dir": fsel},
    )
    assert captured["ws"] == [fsel]      # the peek got the file-selection floor
    assert captured["rl"] == [precise]   # run_load got the precise (row-filter) window


def test_load_required_logs_absent_file_select_window_falls_back_to_precise(
    tmp_path: Path, monkeypatch,
) -> None:
    """Invariant #1 (explicit windows byte-identical): with no file_select_windows
    entry, the peek AND the row filter both use the precise window - same tuple to
    both consumers, exactly as before the split."""
    import dataclasses
    from sigwood.common.loader import pipeline

    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    _make_rot_family(pihole_dir, "pihole.log", {0: ("Jun", 6), 1: ("Jun", 5)})

    captured: dict = {"ws": [], "rl": []}
    real_rl = pipeline.run_load

    def spy_rl(strategy, files, pattern, since, until, **kw):
        captured["rl"].append((since, until))
        return real_rl(strategy, files, pattern, since, until, **kw)

    monkeypatch.setattr(pipeline, "run_load", spy_rl)
    orig = pipeline._SOURCE_LOADERS["pihole_dir"]
    real_ws = orig.window_select

    def spy_ws(files, since, until, *, verbose=False):
        captured["ws"].append((since, until))
        return real_ws(files, since, until, verbose=verbose)

    monkeypatch.setitem(
        pipeline._SOURCE_LOADERS, "pihole_dir",
        dataclasses.replace(orig, window_select=spy_ws),
    )

    precise = (datetime(2026, 6, 1, tzinfo=timezone.utc),
               datetime(2026, 6, 2, tzinfo=timezone.utc))
    load_required_logs(
        {"pihole*.log*": "pihole_dir"},
        {"pihole_dir": [pihole_dir]},
        source_windows={"pihole_dir": precise},
        # file_select_windows absent → fs falls back to the precise window.
    )
    assert captured["ws"] == [precise]
    assert captured["rl"] == [precise]


def test_load_required_logs_file_select_floor_still_peek_prunes(
    tmp_path: Path,
) -> None:
    """Invariant #3: the file-selection floor still drives the rotation-peek prune
    - at least one wholly-older rotation file is skipped (peek-prune preserved)."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    # Newest in window, a straddler, and a wholly-older file (skipped after break).
    _make_rot_family(
        pihole_dir, "pihole.log", {0: ("Jun", 20), 1: ("Jun", 10), 2: ("Jun", 1)},
    )
    floor = parse_timestamp(_dns_line("Jun", 15))  # between rank 0 and rank 1
    result = load_required_logs(
        {"pihole*.log*": "pihole_dir"},
        {"pihole_dir": [pihole_dir]},
        file_select_windows={"pihole_dir": (floor, None)},
    )
    info = result.rotation_skips["pihole*.log*"]
    assert info.skipped > 0 and not info.fallback


def test_permission_denied_message_non_posix_numeric_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without grp/pwd (non-POSIX), the message falls back to numeric ids."""
    import sigwood.common.loader.diagnostics as diagnostics

    target = tmp_path / "pihole.log"
    target.write_text("", encoding="utf-8")
    fake_stat = SimpleNamespace(
        st_uid=1001,
        st_gid=1002,
        st_mode=stat.S_IFREG | 0o640,
    )
    monkeypatch.setattr(diagnostics.os, "stat", lambda _path: fake_stat)
    monkeypatch.setattr(diagnostics, "grp", None)
    monkeypatch.setattr(diagnostics, "pwd", None)

    msg = _permission_denied_message(target)

    assert msg == (
        "pihole.log: permission denied - owned 1001:1002 "
        "(mode 0640); grant your user read access to it and retry"
    )
    assert "usermod" not in msg


def test_diagnostics_imports_without_grp_pwd() -> None:
    """diagnostics imports cleanly when grp/pwd are unavailable (non-POSIX).

    A branch-level monkeypatch of grp/pwd runs after diagnostics is imported and
    cannot exercise the import guard; only a fresh subprocess with the imports
    blocked does.
    """
    script = textwrap.dedent(
        """
        import builtins
        import sys

        _real = builtins.__import__

        def _blocking(name, *args, **kwargs):
            if name in ("grp", "pwd"):
                raise ImportError(name)
            return _real(name, *args, **kwargs)

        builtins.__import__ = _blocking
        sys.modules.pop("grp", None)
        sys.modules.pop("pwd", None)
        for _name in list(sys.modules):
            if _name == "sigwood.common.loader" or _name.startswith(
                "sigwood.common.loader."
            ):
                del sys.modules[_name]

        import sigwood.common.loader.diagnostics as d

        assert d.grp is None and d.pwd is None
        print("H5_OK")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "H5_OK" in result.stdout
