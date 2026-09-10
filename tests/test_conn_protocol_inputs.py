"""Canonical conn protocol inputs and per-source-file observation facts."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sigwood.common.loader as loader
import sigwood.common.loader.pipeline as pipeline
from sigwood.parsers.zeek import (
    _CONN_COLUMNS,
    _CONN_RETAINED_SOURCE_FIELDS,
    _CONN_SOURCE_FLAG_COLUMNS,
)


UTC = timezone.utc
_TS = 1_767_312_000.0


def _window() -> loader.DualWindow:
    start = datetime.fromtimestamp(_TS - 1, tz=UTC)
    return loader.DualWindow((start, start + timedelta(seconds=10)))


def _record(src: str, *, retained: bool) -> dict[str, object]:
    row: dict[str, object] = {
        "_path": "conn",
        "ts": _TS,
        "id.orig_h": src,
        "id.resp_h": "198.51.100.20",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 1.0,
    }
    if retained:
        row.update({field: None for field in _CONN_RETAINED_SOURCE_FIELDS})
    return row


def _write_ndjson(path: Path, src: str, *, retained: bool) -> None:
    path.write_text(json.dumps(_record(src, retained=retained)) + "\n", encoding="utf-8")


def _write_tsv(path: Path, src: str, *, retained: bool, rows: bool = True) -> None:
    fields = [
        "ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "duration"
    ]
    types = ["time", "addr", "addr", "port", "enum", "interval"]
    values = [str(_TS), src, "198.51.100.20", "443", "tcp", "1.0"]
    if retained:
        fields.extend(_CONN_RETAINED_SOURCE_FIELDS)
        types.extend(["string", "string", "count", "count", "count", "count", "count"])
        values.extend(["-"] * len(_CONN_RETAINED_SOURCE_FIELDS))
    body = (
        "#separator \\x09\n"
        "#path\tconn\n"
        + "#fields\t" + "\t".join(fields) + "\n"
        + "#types\t" + "\t".join(types) + "\n"
    )
    if rows:
        body += "\t".join(values) + "\n"
    body += "#close\n"
    path.write_text(body, encoding="utf-8")


def _ordinary(paths: list[Path]):
    return loader.run_load(
        pipeline._SOURCE_LOADERS["zeek_dir"],
        paths,
        "conn*.log*",
        None,
        None,
        show_progress=False,
        _warnings=[],
    )


def _folded(paths: list[Path]):
    return loader.run_folded_source(
        pipeline._SOURCE_LOADERS["zeek_dir"],
        loader.build_source_snapshot(paths, "zeek_dir"),
        "conn*.log*",
        _window(),
        loader.SinkPlan((), preserve_frame=True),
        warnings=[],
    ).frame


@pytest.mark.parametrize("format_name", ["ndjson", "tsv"])
@pytest.mark.parametrize("reverse", [False, True])
def test_conn_source_flags_are_per_file_across_routes_and_orders(
    tmp_path: Path, format_name: str, reverse: bool
) -> None:
    supplied = tmp_path / "conn.a.log"
    absent = tmp_path / "conn.b.log"
    writer = _write_ndjson if format_name == "ndjson" else _write_tsv
    writer(supplied, "192.0.2.10", retained=True)
    writer(absent, "192.0.2.11", retained=False)
    paths = [supplied, absent]
    if reverse:
        paths.reverse()

    ordinary = _ordinary(paths).sort_values("src").reset_index(drop=True)
    folded = _folded(paths).sort_values("src").reset_index(drop=True)
    assert ordinary[list(_CONN_SOURCE_FLAG_COLUMNS)].dtypes.tolist() == [bool] * 7
    assert folded[list(_CONN_SOURCE_FLAG_COLUMNS)].dtypes.tolist() == [bool] * 7
    assert ordinary.loc[0, list(_CONN_SOURCE_FLAG_COLUMNS)].tolist() == [True] * 7
    assert ordinary.loc[1, list(_CONN_SOURCE_FLAG_COLUMNS)].tolist() == [False] * 7
    assert folded[list(_CONN_SOURCE_FLAG_COLUMNS)].to_dict("records") == ordinary[
        list(_CONN_SOURCE_FLAG_COLUMNS)
    ].to_dict("records")
    assert ordinary.loc[0, list(_CONN_RETAINED_SOURCE_FIELDS)].isna().all()


def test_folded_ndjson_observes_later_valid_record_for_every_chunk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "conn.log"
    oversized = json.dumps({"ts": _TS, "service": "http", "pad": "x" * (1024 * 1024)})
    rows = [
        '{"broken"',
        '["not-an-object"]',
        json.dumps({"ts": None, "service": "dns"}),
        oversized,
        json.dumps(_record("192.0.2.10", retained=False)),
        json.dumps({**_record("192.0.2.11", retained=False), "service": None}),
    ]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    monkeypatch.setattr(pipeline, "MAX_CHUNK_ROWS", 1)

    frame = _folded([path]).sort_values("src").reset_index(drop=True)
    assert frame["_source_has_service"].tolist() == [True, True]
    for field in _CONN_RETAINED_SOURCE_FIELDS[1:]:
        assert frame[f"_source_has_{field}"].tolist() == [False, False]


def test_zero_row_conn_inputs_return_the_25_column_canonical_frame(tmp_path: Path) -> None:
    header_only = tmp_path / "conn.header.log"
    rejected = tmp_path / "conn.rejected.log"
    _write_tsv(header_only, "192.0.2.10", retained=True, rows=False)
    rejected.write_text('{"ts":null,"service":null}\n{"broken"\n', encoding="utf-8")

    for path in (header_only, rejected):
        assert tuple(_ordinary([path]).columns) == _CONN_COLUMNS
        assert tuple(_folded([path]).columns) == _CONN_COLUMNS


@pytest.mark.parametrize("format_name", ["ndjson", "tsv"])
def test_originator_port_is_canonical_across_routes(
    tmp_path: Path, format_name: str
) -> None:
    path = tmp_path / "conn.log"
    if format_name == "ndjson":
        record = _record("192.0.2.10", retained=True)
        record["id.orig_p"] = 51514
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    else:
        fields = "ts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration"
        types = "time\taddr\tport\taddr\tport\tenum\tinterval"
        path.write_text(
            "#separator \\x09\n#path\tconn\n"
            f"#fields\t{fields}\n#types\t{types}\n"
            f"{_TS}\t192.0.2.10\t51514\t198.51.100.20\t443\ttcp\t1.0\n#close\n",
            encoding="utf-8",
        )
    assert _ordinary([path]).iloc[0]["orig_port"] == 51514
    assert _folded([path]).iloc[0]["orig_port"] == 51514
