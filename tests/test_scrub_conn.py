from __future__ import annotations

import gzip
import importlib.util
import ipaddress
import json
from pathlib import Path
import random
import sys

import pytest


_TOOL = Path(__file__).resolve().parents[1] / "tools" / "scrub_conn.py"
_SPEC = importlib.util.spec_from_file_location("sigwood_scrub_conn", _TOOL)
assert _SPEC is not None and _SPEC.loader is not None
scrub_conn = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = scrub_conn
_SPEC.loader.exec_module(scrub_conn)

# The tool takes the capture's internal ranges as an argument; these two are the
# fixtures' own and carry no meaning outside this file.
_SOURCE_INTERNAL = (
    ipaddress.ip_network("10.1.0.0/24"),
    ipaddress.ip_network("10.2.0.0/24"),
)


def _row(
    source: str,
    destination: str,
    *,
    ts: float = 1_700_000_000.0,
    orig_bytes: object = 1,
    uid: str = "ColdUid",
    **extra: object,
) -> dict[str, object]:
    return {
        "ts": ts,
        "uid": uid,
        "id.orig_h": source,
        "id.orig_p": 49152,
        "id.resp_h": destination,
        "id.resp_p": 443,
        "proto": "tcp",
        "orig_bytes": orig_bytes,
        "duration": 0.25,
        "conn_state": "SF",
        **extra,
    }


def _write(path: Path, rows: list[dict[str, object]]) -> Path:
    opener = gzip.open if path.suffix == ".gz" else path.open
    if path.suffix == ".gz":
        with opener(path, "wt", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
    else:
        with opener("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
    return path


def _read(path: Path) -> list[dict[str, object]]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _scrub(
    tmp_path: Path,
    rows: list[dict[str, object]],
    *,
    top_hosts: int = 30,
    delta: float = 1234.5,
) -> tuple[scrub_conn.ScrubReceipt, list[dict[str, object]], Path, Path]:
    source = _write(tmp_path / "conn.log", rows)
    output = tmp_path / "conn-public.log.gz"
    receipt = scrub_conn.scrub_file(
        source,
        output,
        source_internal=_SOURCE_INTERNAL,
        top_hosts=top_hosts,
        rng=random.Random(3759),
        timestamp_delta=delta,
    )
    return receipt, _read(output), source, output


def test_scrub_preserves_allowed_shape_but_replaces_identity_and_absolute_time(
    tmp_path: Path,
) -> None:
    rows = [
        _row(
            "10.1.0.4",
            "100.64.1.1",
            ts=100.0,
            uid="C-original",
            community_id="1:old",
            service="ssl",
        ),
        _row("10.1.0.4", "10.2.0.9", ts=103.25, uid="C-other"),
    ]
    receipt, output, source, target = _scrub(tmp_path, rows, delta=900.0)

    assert receipt.rows_output == 2
    assert [row["ts"] for row in output] == [1000.0, 1003.25]
    assert all(row["uid"] not in {"C-original", "C-other"} for row in output)
    assert all("community_id" not in row for row in output)
    assert output[0]["id.orig_p"] == 49152
    assert output[0]["id.resp_p"] == 443
    assert output[0]["orig_bytes"] == 1
    assert output[0]["duration"] == 0.25
    assert output[0]["conn_state"] == "SF"
    assert scrub_conn.verify_output(source, target, len(_SOURCE_INTERNAL))[0] == 2


def test_raw_orig_bytes_plus_row_count_beats_more_low_byte_rows(tmp_path: Path) -> None:
    rows = [_row("10.1.0.1", "100.64.1.1", orig_bytes=1000)]
    rows.extend(_row("10.1.0.1", "100.64.1.2", orig_bytes=1) for _ in range(20))
    receipt, output, _, _ = _scrub(tmp_path, rows, top_hosts=1)
    assert receipt.rows_output == 1
    assert receipt.rows_tail == 20
    assert len({row["id.resp_h"] for row in output}) == 1


def test_all_zero_metric_falls_back_to_row_count(tmp_path: Path) -> None:
    rows = [_row("10.1.0.1", "100.64.1.1", orig_bytes=0)]
    rows.extend(_row("10.1.0.1", "100.64.1.2", orig_bytes="-") for _ in range(2))
    receipt, output, _, _ = _scrub(tmp_path, rows, top_hosts=1)
    assert receipt.rows_output == 2
    assert receipt.rows_tail == 1
    assert len({row["id.resp_h"] for row in output}) == 1


def test_equal_axis_scores_break_by_original_address_label(tmp_path: Path) -> None:
    rows = [
        _row("10.1.0.1", "100.64.2.2", orig_bytes=10),
        _row("10.1.0.1", "100.64.2.1", orig_bytes=10),
    ]
    analysis = scrub_conn.analyze(_write(tmp_path / "conn.log", rows), _SOURCE_INTERNAL)
    selection = scrub_conn.select_external(analysis, 1)
    assert selection.destination == {ipaddress.ip_address("100.64.2.1")}


def test_source_and_destination_axis_top_sets_are_unioned(tmp_path: Path) -> None:
    rows = [
        _row("100.64.1.1", "10.1.0.1", orig_bytes=20),
        _row("10.1.0.1", "100.64.2.1", orig_bytes=30),
    ]
    receipt, output, _, _ = _scrub(tmp_path, rows, top_hosts=1)
    assert receipt.retained_external_identities == 2
    assert len(output) == 2


@pytest.mark.parametrize(
    "peer",
    ["224.0.0.1", "169.254.1.2", "127.0.0.1", "0.0.0.0", "255.255.255.255"],
)
def test_exact_non_unicast_peer_categories_drop_the_row(
    tmp_path: Path, peer: str
) -> None:
    rows = [_row("10.1.0.1", peer), _row("10.1.0.1", "100.64.1.1")]
    receipt, output, _, _ = _scrub(tmp_path, rows)
    assert receipt.rows_non_unicast == 1
    assert len(output) == 1


def test_unmapped_private_unicast_hard_stops_before_output(tmp_path: Path) -> None:
    source = _write(
        tmp_path / "conn.log",
        [_row("10.1.0.1", "10.9.0.4")],
    )
    output = tmp_path / "conn-public.log.gz"
    with pytest.raises(scrub_conn.ScrubError, match="unmapped private unicast"):
        scrub_conn.scrub_file(
            source, output, source_internal=_SOURCE_INTERNAL, rng=random.Random(1)
        )
    assert not output.exists()


def test_dense_internal_range_is_mapped_without_replacement(tmp_path: Path) -> None:
    rows = [
        _row(f"10.1.0.{octet}", "100.64.1.1", uid=f"C{octet}")
        for octet in range(1, 255)
    ]
    _, output, _, _ = _scrub(tmp_path, rows)
    mapped = {str(row["id.orig_h"]) for row in output}
    assert len(mapped) == 254
    assert all(ipaddress.ip_address(value) in ipaddress.ip_network("192.168.1.0/24") for value in mapped)


def test_mapping_pools_exclude_target_addresses_seen_anywhere_in_input(
    tmp_path: Path,
) -> None:
    rows = [
        _row("10.1.0.1", "100.64.1.1"),
        _row("192.168.1.1", "192.0.2.1"),
    ]
    _, output, source, target = _scrub(tmp_path, rows)
    emitted = {
        str(row[key])
        for row in output
        for key in ("id.orig_h", "id.resp_h")
    }
    assert emitted.isdisjoint({"192.168.1.1", "192.0.2.1"})
    assert scrub_conn.verify_output(source, target, len(_SOURCE_INTERNAL))[0] == 1


def test_union_capacity_is_refused_before_mapping(tmp_path: Path) -> None:
    rows: list[dict[str, object]] = []
    for number in range(1, 401):
        rows.append(_row(str(ipaddress.ip_address(0x0B000000 + number)), "10.1.0.1"))
        rows.append(_row("10.1.0.1", str(ipaddress.ip_address(0x0C000000 + number))))
    source = _write(tmp_path / "conn.log", rows)
    analysis = scrub_conn.analyze(source, _SOURCE_INTERNAL)
    with pytest.raises(scrub_conn.ScrubError, match="exceeds 762"):
        scrub_conn.select_external(analysis, 400)


def test_verifier_checks_all_ip_literals_not_only_endpoint_fields(tmp_path: Path) -> None:
    source = _write(tmp_path / "source.log", [_row("10.1.0.1", "100.64.1.1")])
    output = _write(
        tmp_path / "candidate.gz",
        [
            _row(
                "192.168.1.1",
                "192.0.2.1",
                nested={"forgotten_address": "100.64.1.9"},
            )
        ],
    )
    with pytest.raises(scrub_conn.ScrubError, match="outside sanctioned"):
        scrub_conn.verify_output(source, output, len(_SOURCE_INTERNAL))


def test_verifier_rejects_any_input_output_address_intersection(tmp_path: Path) -> None:
    source = _write(
        tmp_path / "source.log",
        [_row("10.1.0.1", "100.64.1.1", note="192.0.2.1")],
    )
    output = _write(
        tmp_path / "candidate.gz",
        [_row("192.168.1.1", "192.0.2.1")],
    )
    with pytest.raises(scrub_conn.ScrubError, match="intersection"):
        scrub_conn.verify_output(source, output, len(_SOURCE_INTERNAL))


def test_cli_has_no_seed_or_timestamp_delta_option() -> None:
    args = scrub_conn.parse_args(
        ["input.log.gz", "output.log.gz", "--source-internal=10.1.0.0/24"]
    )
    assert vars(args) == {
        "source": Path("input.log.gz"),
        "output": Path("output.log.gz"),
        "source_internal": ["10.1.0.0/24"],
        "top_hosts": 30,
    }


def test_cli_requires_the_capture_internal_ranges() -> None:
    with pytest.raises(SystemExit):
        scrub_conn.parse_args(["input.log.gz", "output.log.gz"])


def test_source_networks_must_be_private_and_clear_the_output_ranges() -> None:
    assert [str(net) for net in scrub_conn.parse_source_internal(["10.1.0.0/24"])] == [
        "10.1.0.0/24"
    ]
    for value in ("100.64.0.0/10", "203.0.113.0/24", "192.168.1.0/24", "nonsense"):
        with pytest.raises(scrub_conn.ScrubError):
            scrub_conn.parse_source_internal([value])
    with pytest.raises(scrub_conn.ScrubError):
        scrub_conn.parse_source_internal(["10.0.0.0/8", "10.0.0.0/24"])
    with pytest.raises(scrub_conn.ScrubError):
        scrub_conn.parse_source_internal([])
