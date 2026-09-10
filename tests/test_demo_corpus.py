"""Tests for the demo corpus generator (demo/gen_corpus.py).

demo/ is not a package; the generator module is loaded by file path. Fixtures
use RFC 5737 / RFC 1918 space, and timestamps derive from the runtime clock
(RFC 3164 carries no year - a literal date would rot).
"""

from __future__ import annotations

import importlib.util
import json
import math
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sigwood.common.loader as loader
from sigwood import runner
from sigwood.common import config as config_module
from sigwood.common.loader import load_pihole, load_syslog
from sigwood.detectors import beacon, dnsblock, exfil
from sigwood.detectors.dns import DEFAULT_CONFIG as DNS_DEFAULT_CONFIG
from sigwood.parsers.dnsmasq import parse_line as parse_dnsmasq_line
from sigwood.parsers.syslog import parse_timestamp

_GEN_CORPUS_PATH = Path(__file__).resolve().parent.parent / "demo" / "gen_corpus.py"
_DEMO_CONFIG_PATH = Path(__file__).resolve().parent.parent / "demo" / "sigwood.toml"
_spec = importlib.util.spec_from_file_location("gen_corpus", _GEN_CORPUS_PATH)
assert _spec is not None and _spec.loader is not None
gen_corpus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen_corpus)


_OLD_CONN_KEYS = {
    "_path", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "orig_bytes", "resp_bytes", "conn_state", "local_orig", "duration",
}
_RETAINED_CONN_FIELDS = {
    "service", "history", "missed_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes",
}


def _rng_for(seed: int = 3759):
    return lambda channel: random.Random(seed ^ gen_corpus.FLOW[channel])


class _RecordingRandom:
    def __init__(self, channel: str, seed: int, traces: dict[str, list[tuple]]) -> None:
        self._random = random.Random(seed)
        self._channel = channel
        self._traces = traces

    def __getattr__(self, name: str):
        method = getattr(self._random, name)

        def recorded(*args, **kwargs):
            result = method(*args, **kwargs)
            self._traces.setdefault(self._channel, []).append((name, args, kwargs, result))
            return result

        return recorded


def _recording_rng_for(traces: dict[str, list[tuple]], seed: int = 3759):
    return lambda channel: _RecordingRandom(channel, seed ^ gen_corpus.FLOW[channel], traces)


def _exercise_all_channels(
    traces: dict[str, list[tuple]], epoch0: float, *, include_protocol: bool
) -> list[dict]:
    rng_for = _recording_rng_for(traces)
    conn_rows: list[dict] = []
    gen_corpus._gen_conn(conn_rows, rng_for, epoch0, include_protocol=include_protocol)
    apex = gen_corpus._gen_dns([], rng_for, epoch0)
    anchor = datetime.fromtimestamp(epoch0, tz=timezone.utc)
    gen_corpus._gen_pihole([], rng_for, anchor, apex)
    gen_corpus._gen_syslog([], rng_for, anchor)
    gen_corpus._gen_bench_conn([], rng_for, epoch0)
    return conn_rows


def _run_generator(
    monkeypatch,
    out_dir: Path,
    *,
    seed: int = 3759,
    anchor: str = "2026-06-01T00:00:00",
    scenario: str = "demo",
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "gen_corpus.py", str(out_dir), "--seed", str(seed), "--anchor", anchor,
            "--scenario", scenario,
        ],
    )
    gen_corpus.main()


def test_conn_metadata_is_deterministic_and_zeek_unset_fields_are_absent() -> None:
    sf = gen_corpus._conn_metadata(443, "SF", 1_201, 0)
    assert sf == {
        "service": "ssl",
        "history": "ShADadFf",
        "missed_bytes": 0,
        "orig_pkts": 2,
        "resp_pkts": 0,
        "orig_ip_bytes": 1_281,
        "resp_ip_bytes": 0,
    }
    assert gen_corpus._conn_metadata(22, "S1", 1, 1)["service"] == "ssh"
    assert gen_corpus._conn_metadata(53, "S0", 0, 0)["history"] == "S"
    assert gen_corpus._conn_metadata(80, "REJ", 1_200, 1_200)["history"] == "Sr"
    assert gen_corpus._conn_metadata(8443, "RSTO", 1, 1)["history"] == "ShADadR"
    unknown = gen_corpus._conn_metadata(9_999, "FUTURE", 1, 1)
    assert "service" not in unknown
    assert "history" not in unknown
    assert set(unknown) == _RETAINED_CONN_FIELDS - {"service", "history"}


def test_originator_port_is_draw_free_and_derived_from_row_index() -> None:
    rows: list[dict] = []
    for index in range(3):
        gen_corpus._conn_row(
            rows, 1_767_312_000.0 + index, "192.0.2.10", "198.51.100.20", 443,
            "tcp", 10, 20, "SF", 1.0,
        )
    assert [row["id.orig_p"] for row in rows] == [49152, 49153, 49154]


def test_protocol_fixtures_are_exact_isolated_and_draw_decorrelated() -> None:
    epoch0 = datetime(2026, 6, 1, tzinfo=timezone.utc).timestamp()
    without_traces: dict[str, list[tuple]] = {}
    with_traces: dict[str, list[tuple]] = {}
    without = _exercise_all_channels(without_traces, epoch0, include_protocol=False)
    enabled = _exercise_all_channels(with_traces, epoch0, include_protocol=True)

    protocol_addresses = {
        gen_corpus.PROTOCOL_MISMATCH_SOURCE,
        gen_corpus.PROTOCOL_MISMATCH_DESTINATION,
        gen_corpus.PROTOCOL_SHAPE_SOURCE,
        gen_corpus.PROTOCOL_SHAPE_DESTINATION,
    }
    old_enabled = [
        {key: row[key] for key in _OLD_CONN_KEYS}
        for row in enabled
        if row["id.orig_h"] not in protocol_addresses
        and row["id.resp_h"] not in protocol_addresses
    ]
    old_without = [{key: row[key] for key in _OLD_CONN_KEYS} for row in without]
    assert old_enabled == old_without
    assert set(without_traces) == set(gen_corpus.FLOW) - {
        "protocol_mismatch", "protocol_shape"
    }
    for channel, trace in without_traces.items():
        assert with_traces[channel] == trace

    mismatch = [
        row for row in enabled
        if row["id.orig_h"] == gen_corpus.PROTOCOL_MISMATCH_SOURCE
    ]
    shape = [
        row for row in enabled
        if row["id.orig_h"] == gen_corpus.PROTOCOL_SHAPE_SOURCE
    ]
    assert len(mismatch) == gen_corpus.PROTOCOL_MISMATCH_COUNT == 6
    assert len(shape) == 1
    assert {
        (row["id.orig_h"], row["id.resp_h"], row["id.resp_p"], row["proto"])
        for row in mismatch
    } == {(
        gen_corpus.PROTOCOL_MISMATCH_SOURCE,
        gen_corpus.PROTOCOL_MISMATCH_DESTINATION,
        443,
        "tcp",
    )}
    assert {row["service"] for row in mismatch} == {"ssh"}
    assert {row["history"] for row in mismatch} == {"ShADadFf"}
    assert {row["conn_state"] for row in mismatch} == {"SF"}
    assert max(row["ts"] for row in mismatch) - min(row["ts"] for row in mismatch) > 4_400
    assert len(mismatch) < beacon.DEFAULT_CONFIG["min_connections"]

    shape_row = shape[0]
    assert (
        shape_row["id.resp_h"], shape_row["id.resp_p"], shape_row["proto"],
        shape_row["service"], shape_row["conn_state"], shape_row["history"],
    ) == (gen_corpus.PROTOCOL_SHAPE_DESTINATION, 443, "tcp", "ssl", "SF", "ShADad")
    assert not ({"F", "f"} & set(shape_row["history"]))
    assert shape_row["orig_pkts"] > 0 and shape_row["resp_pkts"] > 0
    assert shape_row["resp_ip_bytes"] / shape_row["orig_ip_bytes"] > 500
    origin_share = shape_row["orig_ip_bytes"] / (
        shape_row["orig_ip_bytes"] + shape_row["resp_ip_bytes"]
    )
    assert origin_share < 0.01
    for value in (
        shape_row["duration"], shape_row["orig_ip_bytes"], shape_row["resp_ip_bytes"],
        shape_row["orig_pkts"], shape_row["resp_pkts"],
        shape_row["orig_ip_bytes"] / shape_row["orig_pkts"],
        shape_row["resp_ip_bytes"] / shape_row["resp_pkts"], origin_share,
    ):
        assert math.isfinite(value) and value >= 0
    assert set(shape_row["history"]) == {"S", "h", "A", "D", "a", "d"}

    old_addresses = {
        address
        for row in without
        for address in (row["id.orig_h"], row["id.resp_h"])
    }
    assert protocol_addresses.isdisjoint(old_addresses)
    old_pairs = {(row["id.orig_h"], row["id.resp_h"]) for row in without}
    old_flows = {
        (row["id.orig_h"], row["id.resp_h"], row["id.resp_p"], row["proto"])
        for row in without
    }
    for row in mismatch + shape:
        assert (row["id.orig_h"], row["id.resp_h"]) not in old_pairs
        assert (row["id.orig_h"], row["id.resp_h"], row["id.resp_p"], row["proto"]) not in old_flows


def test_generated_demo_conn_fields_are_observed_and_protocol_rows_are_demo_only(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    demo_dir = tmp_path / "demo"
    bench_dir = tmp_path / "bench"
    _run_generator(monkeypatch, demo_dir)
    capsys.readouterr()
    _run_generator(monkeypatch, bench_dir, scenario="bench")
    capsys.readouterr()

    demo_log = demo_dir / "zeek" / "conn.log"
    raw_rows = [json.loads(line) for line in demo_log.read_text(encoding="utf-8").splitlines()]
    assert len(raw_rows) == 2_643
    for field in _RETAINED_CONN_FIELDS - {"service", "history"}:
        assert all(field in row for row in raw_rows)
    assert any(row.get("service") == "ssh" for row in raw_rows)
    shape_bytes = sum(
        row["orig_bytes"] + row["resp_bytes"]
        for row in raw_rows
        if row["id.orig_h"] == gen_corpus.PROTOCOL_SHAPE_SOURCE
    )
    total_bytes = sum(row["orig_bytes"] + row["resp_bytes"] for row in raw_rows)
    assert shape_bytes / total_bytes < 0.10

    frame = loader.run_load(
        loader.pipeline._SOURCE_LOADERS["zeek_dir"],
        [demo_log],
        "conn*.log*",
        None,
        None,
        show_progress=False,
        _warnings=[],
    )
    assert frame[[f"_source_has_{field}" for field in _RETAINED_CONN_FIELDS]].all().all()

    bench_rows = [
        json.loads(line)
        for line in (bench_dir / "zeek" / "conn.log").read_text(encoding="utf-8").splitlines()
    ]
    assert len(bench_rows) == 530
    protocol_sources = {
        gen_corpus.PROTOCOL_MISMATCH_SOURCE, gen_corpus.PROTOCOL_SHAPE_SOURCE
    }
    assert not any(row["id.orig_h"] in protocol_sources for row in bench_rows)

    sibling_output = tmp_path / "siblings.json"
    assert runner.run(
        {
            "sigwood": {
                "root": "",
                "warn_above": 0,
                "default_window": "7d",
            }
        },
        detect="beacon,scan,exfil",
        zeek_dir=demo_dir / "zeek",
        output_format="json",
        output_file=sibling_output,
        no_allowlist=True,
        quiet=True,
        use_utc=True,
    ) == 0
    findings = json.loads(sibling_output.read_text(encoding="utf-8"))["findings"]
    assert [(finding["detector"], finding["title"]) for finding in findings] == [
        ("beacon", f"{gen_corpus.WEBHOST} → {gen_corpus.C2_PRIMARY}:443/tcp"),
        ("beacon", f"{gen_corpus.WEBHOST} → {gen_corpus.C2_SECONDARY}:8443/tcp"),
        ("exfil", f"{gen_corpus.WEBHOST} → {gen_corpus.EXFIL_DESTINATION}"),
    ]


def test_sysline_ts_local_render_and_parse_back(pin_tz) -> None:
    """Syslog stamps render the anchor's LOCAL wall-clock and parse back to the
    anchor's epoch - the cross-signal correlation the demo depends on: the
    parsed syslog timeline must line up with the conn/dns epoch rows on the
    box that generated the corpus."""
    pin_tz("Etc/GMT+6")
    anchor = (datetime.now(timezone.utc) - timedelta(days=30)).replace(
        minute=0, second=0, microsecond=0
    )
    loc = anchor.astimezone()
    expected_stamp = f"{loc.strftime('%b')} {loc.day:2d} {loc.strftime('%H:%M:%S')}"
    stamp = gen_corpus._sysline_ts(anchor, 0)
    assert stamp == expected_stamp
    parsed = parse_timestamp(f"{stamp} host1 sshd[1]: session opened")
    assert parsed is not None
    assert parsed.timestamp() == anchor.timestamp()


def test_pihole_slice_main_wiring_is_deterministic(
    tmp_path: Path,
    monkeypatch,
    pin_tz,
    capsys,
) -> None:
    pin_tz("Etc/GMT+6")
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"

    _run_generator(monkeypatch, out_a)
    first_stdout = capsys.readouterr().out
    _run_generator(monkeypatch, out_b)
    second_stdout = capsys.readouterr().out

    pihole_a = out_a / "pihole" / "pihole.log"
    pihole_b = out_b / "pihole" / "pihole.log"
    assert pihole_a.exists()
    assert pihole_b.exists()
    assert pihole_a.read_bytes() == pihole_b.read_bytes()
    assert "pihole/pihole.log" in first_stdout
    assert "DGA apex:" in first_stdout
    assert "pihole/pihole.log" in second_stdout
    assert (out_a / "zeek" / "conn.log").exists()
    assert (out_a / "zeek" / "dns.log").exists()
    assert (out_a / "syslog" / "messages").exists()

    config_text = _DEMO_CONFIG_PATH.read_text(
        encoding="utf-8",
    )
    assert 'pihole_dir = "demo/corpus/pihole"' in config_text
    assert 'detect = "dns, beacon, exfil, syslog"' in config_text


def test_generated_exfil_rows_are_one_originator_dominant_pair() -> None:
    rows: list[dict] = []
    epoch0 = datetime(2026, 6, 1, tzinfo=timezone.utc).timestamp()

    def rng_for(channel: str) -> random.Random:
        return random.Random(3759 ^ gen_corpus.FLOW[channel])

    gen_corpus._gen_conn(rows, rng_for, epoch0)
    exfil_rows = [row for row in rows if row["id.resp_h"] == gen_corpus.EXFIL_DESTINATION]

    assert len(exfil_rows) == gen_corpus.EXFIL_CONNECTION_COUNT
    assert {row["id.orig_h"] for row in exfil_rows} == {gen_corpus.WEBHOST}
    assert {row["id.resp_p"] for row in exfil_rows} == {443}
    assert {row["proto"] for row in exfil_rows} == {"tcp"}
    assert {row["conn_state"] for row in exfil_rows} == {"SF"}
    assert {row["local_orig"] for row in exfil_rows} == {True}
    assert sum(row["orig_bytes"] for row in exfil_rows) > exfil.DEFAULT_CONFIG["min_outbound_bytes"]
    total_bytes = sum(row["orig_bytes"] + row["resp_bytes"] for row in exfil_rows)
    assert sum(row["orig_bytes"] for row in exfil_rows) / total_bytes >= exfil.DEFAULT_CONFIG["min_orig_share"]
    assert len(exfil_rows) < beacon.DEFAULT_CONFIG["min_connections"]
    protocol_count = gen_corpus.PROTOCOL_MISMATCH_COUNT + 1
    assert {row["uid"] for row in exfil_rows} == {
        f"C{index:07d}"
        for index in range(
            len(rows) - protocol_count - gen_corpus.EXFIL_CONNECTION_COUNT,
            len(rows) - protocol_count,
        )
    }


def test_demo_config_routes_generated_exfil_to_json_and_text(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    out_dir = tmp_path / "corpus"
    _run_generator(monkeypatch, out_dir)
    capsys.readouterr()
    config = config_module.load(_DEMO_CONFIG_PATH)
    assert config["sigwood"]["detect"] == "dns, beacon, exfil, syslog"

    json_path = tmp_path / "report.json"
    assert runner.run(
        config,
        zeek_dir=out_dir / "zeek",
        output_format="json",
        output_file=json_path,
        scope=frozenset({"zeek_dir"}),
        quiet=True,
    ) == 0
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    exfil_findings = [finding for finding in payload["findings"] if finding["detector"] == "exfil"]
    assert len(exfil_findings) == 1
    evidence = exfil_findings[0]["evidence"]
    assert evidence["src"] == gen_corpus.WEBHOST
    assert evidence["dst"] == gen_corpus.EXFIL_DESTINATION
    assert "destination_count" not in evidence
    assert "members" not in evidence

    text_path = tmp_path / "report.txt"
    assert runner.run(
        config,
        zeek_dir=out_dir / "zeek",
        output_format="text",
        output_file=text_path,
        scope=frozenset({"zeek_dir"}),
        quiet=True,
    ) == 0
    text = text_path.read_text(encoding="utf-8")
    assert f"{gen_corpus.WEBHOST}  →  {gen_corpus.EXFIL_DESTINATION}" in text
    assert "conns=12" in text


def test_bench_conn_count_excludes_duration_control(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    out_dir = tmp_path / "bench"
    _run_generator(monkeypatch, out_dir, scenario="bench")
    capsys.readouterr()
    assert len((out_dir / "zeek" / "conn.log").read_text(encoding="utf-8").splitlines()) == 530


def test_generated_pihole_lines_are_known_dnsmasq_events(
    tmp_path: Path,
    monkeypatch,
    pin_tz,
    capsys,
) -> None:
    pin_tz("Etc/GMT+6")
    out_dir = tmp_path / "corpus"
    _run_generator(monkeypatch, out_dir)
    capsys.readouterr()

    records = []
    for line in (out_dir / "pihole" / "pihole.log").read_text(encoding="utf-8").splitlines():
        record = parse_dnsmasq_line(line)
        assert record is not None, line
        assert record["event_type"] != "unknown", line
        records.append(record)

    event_types = {record["event_type"] for record in records}
    assert {"query", "forwarded", "cached", "reply",
            "gravity_blocked", "regex_blocked"} <= event_types


def test_generated_pihole_story_shape(
    tmp_path: Path,
    monkeypatch,
    pin_tz,
    capsys,
) -> None:
    pin_tz("Etc/GMT+6")
    out_dir = tmp_path / "corpus"
    _run_generator(monkeypatch, out_dir)
    capsys.readouterr()

    frame = load_pihole(out_dir / "pihole")
    query_rows = frame[frame["event_type"] == "query"]
    assert not query_rows.empty
    assert query_rows["src"].value_counts().idxmax() == gen_corpus.WEBHOST

    dga_queries = query_rows[
        query_rows["query"].astype(str).str.endswith(".xyz", na=False)
    ]
    dga_count = dga_queries["query"].nunique()
    assert dga_count == gen_corpus.PIHOLE_DGA_COUNT
    assert dga_count < DNS_DEFAULT_CONFIG["pihole"]["min_cluster_size"]
    assert set(dga_queries["src"]) == {gen_corpus.WEBHOST}

    block_mask = frame["event_type"].isin({"gravity_blocked", "regex_blocked"})
    block_rate = block_mask.sum() / len(frame)
    assert 0.01 <= block_rate <= 0.10

    domain_counts = frame["query"].value_counts()
    assert domain_counts.index[0] == "api.example.com"
    assert domain_counts.iloc[0] / domain_counts.iloc[1] >= 2.0

    lengths = frame["query"].dropna().astype(str).str.len()
    assert lengths.max() / lengths.median() > 3.0
    assert query_rows["qtype"].nunique() >= 4


def test_dnsblock_seed_trips_arrival_through_real_product_route(
    tmp_path: Path,
    monkeypatch,
    pin_tz,
    capsys,
) -> None:
    pin_tz("Etc/GMT+6")
    out_dir = tmp_path / "corpus"
    _run_generator(monkeypatch, out_dir)
    capsys.readouterr()
    output = tmp_path / "dnsblock.json"
    assert runner.run(
        {
            "sigwood": {
                "root": "",
                "warn_above": 0,
                "default_window": "7d",
            }
        },
        detect="dnsblock",
        pihole_dir=out_dir / "pihole",
        output_format="json",
        output_file=output,
        no_allowlist=True,
        quiet=True,
        use_utc=True,
    ) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    arrivals = [
        finding
        for finding in payload["findings"]
        if finding["evidence"].get("kind") == "arrival"
    ]
    assert [finding["title"] for finding in arrivals] == [
        f"{gen_corpus.DNSBLOCK_DEMO_ADDRESS} → example.org"
    ]
    assert arrivals[0]["severity"] == "low"


def test_generated_syslog_has_one_canonical_useradd_member_seed(
    tmp_path: Path,
    monkeypatch,
    pin_tz,
    capsys,
) -> None:
    pin_tz("Etc/GMT+6")
    out_dir = tmp_path / "corpus"
    _run_generator(monkeypatch, out_dir)
    capsys.readouterr()

    frame = load_syslog(out_dir / "syslog", show_progress=False)
    useradd = frame[frame["program"] == "useradd"]
    assert len(useradd) == 1
    assert "UID=0" in useradd.iloc[0]["raw"]
