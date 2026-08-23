"""SEC-3 rename-collision containment and digest fallback disclosure."""

from __future__ import annotations

import io
import json
import warnings
from pathlib import Path

import pandas as pd
import pytest

from sigwood import cli, runner
from sigwood.common import config as cfg
from sigwood.common.loader import sniff_format
from sigwood.common.loader.pipeline import _zeek_normalize
from sigwood.parsers import zeek
from sigwood.outputs._sanitize import strip_control_keep_newlines


CONN_COLUMNS = (
    "src", "dst", "port", "proto", "ts", "bytes", "resp_bytes",
    "duration", "conn_state", "local_orig",
)
DNS_COLUMNS = (
    "ts", "src", "query", "resolver", "qtype", "rtt", "ttl", "rcode",
    "answer", "tc",
)


def _conn_record(index: int = 0, *, collision: bool = True) -> dict[str, object]:
    record: dict[str, object] = {
        "_path": "conn",
        "ts": 1_787_440_000.0 + index * 180.0,
        "id.orig_h": "192.0.2.10",
        "id.resp_h": "198.51.100.20",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 1.0,
        "conn_state": "SF",
        "orig_bytes": 100,
        "resp_bytes": 200,
        "local_orig": True,
    }
    if collision:
        record["src"] = "192.0.2.99"
    return record


def _dns_record() -> dict[str, object]:
    return {
        "_path": "dns",
        "ts": 1_787_440_000.0,
        "id.orig_h": "192.0.2.10",
        "src": "192.0.2.99",
        "id.resp_h": "198.51.100.53",
        "query": "example.test",
        "qclass": 1,
        "qtype": 1,
    }


def _write_ndjson(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


def test_non_string_path_falls_to_blob_without_losing_healthy_sibling(
    tmp_path: Path,
) -> None:
    """The shipped recognizer contains a malformed file and still reads its sibling."""
    hostile = tmp_path / "a-hostile.log"
    healthy = tmp_path / "z-conn.log"
    _write_ndjson(hostile, [{"_path": ["conn"]}])
    _write_ndjson(healthy, [_conn_record(collision=False)])

    assert sniff_format(hostile) == "blob"
    assert sniff_format(healthy) == "conn"


@pytest.mark.parametrize(
    ("log_type", "record", "columns"),
    (("conn", _conn_record(), CONN_COLUMNS), ("dns", _dns_record(), DNS_COLUMNS)),
)
def test_collision_normalizes_to_one_warning_and_ordered_empty_frame(
    log_type: str,
    record: dict[str, object],
    columns: tuple[str, ...],
) -> None:
    sink: list[str] = []
    result = _zeek_normalize(
        pd.DataFrame([record]), f"{log_type}*.log*", warnings=sink,
    )

    assert result.empty
    assert tuple(result.columns) == columns
    assert sink == [
        f"{log_type}.log: skipped 1 row - a source column collides with a "
        f"canonical name; is this a Zeek {log_type}.log?"
    ]


def test_conn_and_dns_apertures_are_ordered_and_in_lockstep() -> None:
    assert zeek._CONN_COLUMNS == CONN_COLUMNS
    assert zeek._DNS_COLUMNS == DNS_COLUMNS
    assert set(zeek._CONN_COLUMNS) == (
        zeek._REQUIRED_COLUMNS["conn"] | zeek._OPTIONAL_COLUMNS["conn"]
    )
    assert set(zeek._DNS_COLUMNS) == (
        zeek._REQUIRED_COLUMNS["dns"] | zeek._OPTIONAL_COLUMNS["dns"]
    )


def test_real_beacon_route_collision_has_no_confident_count_or_future_warning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conn = tmp_path / "conn.log"
    _write_ndjson(conn, [_conn_record(index) for index in range(40)])

    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        assert cli.main(["--detect=beacon", str(conn)]) is None

    captured = capsys.readouterr()
    assert "conn.log: skipped 40 rows - a source column collides" in captured.err
    assert "data found:    none" in captured.out
    assert "records: 40 Zeek conn" not in captured.out
    assert "widen with --all or a longer lookback" not in captured.out
    assert "files found, 0 records in the selected window" not in captured.out
    assert not [item for item in seen if issubclass(item.category, FutureWarning)]


def test_real_digest_route_collision_reaches_digest_empty(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conn = tmp_path / "conn.log"
    _write_ndjson(conn, [_conn_record()])

    assert cli._main(["digest", str(conn)]) == 0

    captured = capsys.readouterr()
    assert "conn.log: skipped 1 row - a source column collides" in captured.err
    assert "recognized as conn, no parseable records - skipping" in captured.err
    assert "summariser failed" not in captured.err
    assert "Unrecognized source" not in captured.out


def _clean_conn_tsv() -> str:
    return (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n"
        "1787440000.0\tC1\t192.0.2.10\t1000\t198.51.100.20\t443\ttcp\n"
    )


def test_digest_fallback_default_is_fixed_and_verbose_detail_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "conn.log").write_text(_clean_conn_tsv(), encoding="utf-8")
    fallback = tmp_path / "sample.log"
    fallback.write_text("orientation sample\n", encoding="utf-8")
    hostile = "boom\x1b]0;title\x07" + "x" * 400

    def _boom(frame, *args, **kwargs):
        del frame, args, kwargs
        raise ValueError(hostile)

    monkeypatch.setattr("sigwood.digest.get_summarizer", lambda schema: _boom)

    runner.run_digest(
        config={"sigwood": {"root": str(tmp_path)}},
        zeek_dir=data,
        schema="conn",
        fallback_blob_path=fallback,
        verbose_level=0,
        quiet=True,
        stream=io.StringIO(),
    )
    default_err = capsys.readouterr().err
    assert "summary could not be built; profiling bytes instead" in default_err
    assert "ValueError" not in default_err
    assert "boom" not in default_err

    runner.run_digest(
        config={"sigwood": {"root": str(tmp_path)}},
        zeek_dir=data,
        schema="conn",
        fallback_blob_path=fallback,
        verbose_level=1,
        quiet=True,
        stream=io.StringIO(),
    )
    verbose_err = capsys.readouterr().err
    assert "summary could not be built; profiling bytes instead" in verbose_err
    assert "ValueError: boom" in verbose_err
    assert "…" in verbose_err
    assert "x" * 201 not in verbose_err
    assert strip_control_keep_newlines(verbose_err) == verbose_err
