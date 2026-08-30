#!/usr/bin/env python3
"""Scrub a gzip Zeek conn JSON-lines export for the public graph asset.

This developer tool deliberately preserves ports, byte volumes, durations,
connection states, relative timing, and the shape of two internal /24s.  The
result is a traffic fingerprint, not an anonymized or general-purpose export.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass, field
import gzip
import ipaddress
import json
import math
import os
from pathlib import Path
import random
import secrets
import string
import sys
import tempfile
from typing import Iterator, Mapping, MutableMapping, Protocol, Sequence, TextIO


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_INTERNAL = (
    ipaddress.ip_network("172.23.8.0/24"),
    ipaddress.ip_network("172.23.16.0/24"),
)
TARGET_INTERNAL = (
    ipaddress.ip_network("192.168.1.0/24"),
    ipaddress.ip_network("192.168.2.0/24"),
)
TARGET_EXTERNAL = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
TARGET_NETWORKS = (*TARGET_INTERNAL, *TARGET_EXTERNAL)
EXTERNAL_CAPACITY = 762
DEFAULT_TOP_HOSTS = 30
UID_ALPHABET = string.ascii_letters + string.digits


class ScrubError(RuntimeError):
    """The source or requested scrub cannot satisfy the privacy contract."""


class RandomSource(Protocol):
    def shuffle(self, value: list[object]) -> None: ...
    def choice(self, value: Sequence[str]) -> str: ...
    def uniform(self, start: float, end: float) -> float: ...


@dataclass
class AxisMetric:
    byte_sum: float = 0.0
    rows: int = 0


@dataclass
class Analysis:
    input_addresses: set[ipaddress._BaseAddress] = field(default_factory=set)
    internal: tuple[set[ipaddress._BaseAddress], set[ipaddress._BaseAddress]] = field(
        default_factory=lambda: (set(), set())
    )
    source_external: dict[ipaddress._BaseAddress, AxisMetric] = field(
        default_factory=lambda: defaultdict(AxisMetric)
    )
    destination_external: dict[ipaddress._BaseAddress, AxisMetric] = field(
        default_factory=lambda: defaultdict(AxisMetric)
    )
    rows_input: int = 0
    rows_eligible: int = 0
    rows_non_unicast: int = 0
    rows_usable: int = 0
    any_positive_metric: bool = False
    min_timestamp: float | None = None


@dataclass(frozen=True)
class Selection:
    source: frozenset[ipaddress._BaseAddress]
    destination: frozenset[ipaddress._BaseAddress]

    @property
    def union(self) -> frozenset[ipaddress._BaseAddress]:
        return self.source | self.destination


@dataclass(frozen=True)
class ScrubReceipt:
    rows_input: int
    rows_eligible: int
    rows_non_unicast: int
    rows_tail: int
    rows_output: int
    external_identities_observed: int
    retained_external_identities: int
    external_capacity: int = EXTERNAL_CAPACITY


def _open_text(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return path.open("r", encoding="utf-8", newline="")


def _rows(path: Path) -> Iterator[tuple[int, MutableMapping[str, object]]]:
    try:
        handle = _open_text(path)
    except OSError as exc:
        raise ScrubError(f"cannot open source: {exc}") from exc
    with handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ScrubError(f"source line {line_number} is not valid JSON") from exc
            if not isinstance(value, dict):
                raise ScrubError(f"source line {line_number} is not a JSON object")
            yield line_number, value


def _ip_literals(value: object) -> Iterator[ipaddress._BaseAddress]:
    if isinstance(value, str):
        try:
            yield ipaddress.ip_address(value)
        except ValueError:
            return
    elif isinstance(value, Mapping):
        for nested in value.values():
            yield from _ip_literals(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            yield from _ip_literals(nested)


def _address(row: Mapping[str, object], key: str, line_number: int) -> ipaddress._BaseAddress:
    raw = row.get(key)
    if not isinstance(raw, str):
        raise ScrubError(f"source line {line_number} has no string {key}")
    try:
        return ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ScrubError(f"source line {line_number} has an invalid {key}") from exc


def _internal_index(address: ipaddress._BaseAddress) -> int | None:
    for index, network in enumerate(SOURCE_INTERNAL):
        if address in network:
            return index
    return None


def _is_non_unicast(address: ipaddress._BaseAddress) -> bool:
    return bool(
        address.is_multicast
        or address.is_link_local
        or address.is_loopback
        or address.is_unspecified
        or address == ipaddress.ip_address("255.255.255.255")
    )


def _clean_metric(value: object) -> float:
    if isinstance(value, bool):
        return 0.0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(number) or number < 0:
        return 0.0
    return number


def _timestamp(value: object, line_number: int) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ScrubError(f"source line {line_number} has an invalid ts") from exc
    if not math.isfinite(number):
        raise ScrubError(f"source line {line_number} has an invalid ts")
    return number


def _classify_eligible_pair(
    source: ipaddress._BaseAddress,
    destination: ipaddress._BaseAddress,
    line_number: int,
) -> tuple[int | None, int | None] | None:
    source_internal = _internal_index(source)
    destination_internal = _internal_index(destination)
    if source_internal is None and destination_internal is None:
        return None
    for address, index in ((source, source_internal), (destination, destination_internal)):
        if index is not None:
            continue
        if _is_non_unicast(address):
            return (-1, -1)
        if address.is_private:
            raise ScrubError(
                f"source line {line_number} has unmapped private unicast in an eligible row"
            )
    return source_internal, destination_internal


def analyze(path: Path) -> Analysis:
    analysis = Analysis()
    for line_number, row in _rows(path):
        analysis.rows_input += 1
        source = _address(row, "id.orig_h", line_number)
        destination = _address(row, "id.resp_h", line_number)
        analysis.input_addresses.update(_ip_literals(row))
        pair = _classify_eligible_pair(source, destination, line_number)
        if pair is None:
            continue
        analysis.rows_eligible += 1
        if pair == (-1, -1):
            analysis.rows_non_unicast += 1
            continue
        source_internal, destination_internal = pair
        analysis.rows_usable += 1
        if source_internal is not None:
            analysis.internal[source_internal].add(source)
        if destination_internal is not None:
            analysis.internal[destination_internal].add(destination)
        metric = _clean_metric(row.get("orig_bytes"))
        analysis.any_positive_metric |= metric > 0
        if source_internal is None:
            aggregate = analysis.source_external[source]
            aggregate.byte_sum += metric
            aggregate.rows += 1
        if destination_internal is None:
            aggregate = analysis.destination_external[destination]
            aggregate.byte_sum += metric
            aggregate.rows += 1
        timestamp = _timestamp(row.get("ts"), line_number)
        analysis.min_timestamp = (
            timestamp
            if analysis.min_timestamp is None
            else min(analysis.min_timestamp, timestamp)
        )
    if analysis.rows_input == 0:
        raise ScrubError("source has no rows")
    if analysis.rows_usable == 0:
        raise ScrubError("source has no usable rows in the explicitly mapped ranges")
    return analysis


def _top_axis(
    values: Mapping[ipaddress._BaseAddress, AxisMetric],
    count: int,
    any_positive: bool,
) -> frozenset[ipaddress._BaseAddress]:
    def key(item: tuple[ipaddress._BaseAddress, AxisMetric]) -> tuple[float, str]:
        address, metric = item
        score = metric.byte_sum + metric.rows if any_positive else 2 * metric.rows
        return -score, str(address)

    return frozenset(address for address, _ in sorted(values.items(), key=key)[:count])


def select_external(analysis: Analysis, top_hosts: int) -> Selection:
    if top_hosts < 1:
        raise ScrubError("top-hosts must be positive")
    selection = Selection(
        _top_axis(analysis.source_external, top_hosts, analysis.any_positive_metric),
        _top_axis(analysis.destination_external, top_hosts, analysis.any_positive_metric),
    )
    if len(selection.union) > EXTERNAL_CAPACITY:
        raise ScrubError(
            f"retained external identity count exceeds {EXTERNAL_CAPACITY}"
        )
    return selection


def _pool(
    network: ipaddress.IPv4Network,
    forbidden: set[ipaddress._BaseAddress],
) -> list[ipaddress.IPv4Address]:
    return [address for address in network.hosts() if address not in forbidden]


def _random_mapping(
    sources: Sequence[ipaddress._BaseAddress],
    targets: list[ipaddress.IPv4Address],
    rng: RandomSource,
) -> dict[ipaddress._BaseAddress, ipaddress.IPv4Address]:
    if len(sources) > len(targets):
        raise ScrubError("mapping target pool is too small")
    rng.shuffle(targets)  # type: ignore[arg-type]
    return dict(zip(sorted(sources, key=str), targets))


def build_mappings(
    analysis: Analysis,
    selection: Selection,
    rng: RandomSource,
) -> dict[ipaddress._BaseAddress, ipaddress.IPv4Address]:
    mapping: dict[ipaddress._BaseAddress, ipaddress.IPv4Address] = {}
    for sources, network in zip(analysis.internal, TARGET_INTERNAL):
        mapping.update(
            _random_mapping(tuple(sources), _pool(network, analysis.input_addresses), rng)
        )
    external_pool: list[ipaddress.IPv4Address] = []
    for network in TARGET_EXTERNAL:
        external_pool.extend(_pool(network, analysis.input_addresses))
    mapping.update(_random_mapping(tuple(selection.union), external_pool, rng))
    return mapping


def _new_uid(rng: RandomSource, seen: set[str]) -> str:
    while True:
        value = "C" + "".join(rng.choice(UID_ALPHABET) for _ in range(17))
        if value not in seen:
            seen.add(value)
            return value


def _write_candidate(
    source: Path,
    candidate: Path,
    analysis: Analysis,
    selection: Selection,
    mapping: Mapping[ipaddress._BaseAddress, ipaddress.IPv4Address],
    rng: RandomSource,
    timestamp_delta: float,
) -> tuple[int, int]:
    rows_output = 0
    rows_tail = 0
    seen_uids: set[str] = set()
    with candidate.open("wb") as raw_handle:
        os.chmod(candidate, 0o600)
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_handle, mtime=0) as zipped:
            for line_number, row in _rows(source):
                source_address = _address(row, "id.orig_h", line_number)
                destination_address = _address(row, "id.resp_h", line_number)
                pair = _classify_eligible_pair(
                    source_address, destination_address, line_number
                )
                if pair is None or pair == (-1, -1):
                    continue
                external = {
                    address
                    for address, internal in zip(
                        (source_address, destination_address), pair
                    )
                    if internal is None
                }
                if external - selection.union:
                    rows_tail += 1
                    continue
                try:
                    row["id.orig_h"] = str(mapping[source_address])
                    row["id.resp_h"] = str(mapping[destination_address])
                except KeyError as exc:
                    raise ScrubError("an eligible address has no mapping") from exc
                row["ts"] = _timestamp(row.get("ts"), line_number) + timestamp_delta
                row["uid"] = _new_uid(rng, seen_uids)
                for key in tuple(row):
                    if key == "community_id" or key.endswith(".community_id"):
                        row.pop(key)
                data = json.dumps(row, ensure_ascii=True, separators=(",", ":"))
                zipped.write(data.encode("utf-8") + b"\n")
                rows_output += 1
    if rows_output == 0:
        raise ScrubError("selection produced no output rows")
    return rows_output, rows_tail


def verify_output(source: Path, output: Path) -> tuple[int, int]:
    input_addresses: set[ipaddress._BaseAddress] = set()
    for _, row in _rows(source):
        input_addresses.update(_ip_literals(row))
    output_addresses: set[ipaddress._BaseAddress] = set()
    rows = 0
    for _, row in _rows(output):
        rows += 1
        addresses = set(_ip_literals(row))
        if not addresses:
            raise ScrubError("output verifier found a row with no addresses")
        for address in addresses:
            if not any(address in network for network in TARGET_NETWORKS):
                raise ScrubError("output verifier found an address outside sanctioned ranges")
            output_addresses.add(address)
    if not rows:
        raise ScrubError("output verifier found no rows")
    overlap = input_addresses & output_addresses
    if overlap:
        raise ScrubError("output verifier found an input/output address intersection")
    return rows, len(output_addresses)


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        return False
    return True


def scrub_file(
    source: Path,
    output: Path,
    *,
    top_hosts: int = DEFAULT_TOP_HOSTS,
    rng: RandomSource | None = None,
    timestamp_delta: float | None = None,
) -> ScrubReceipt:
    source = source.expanduser().resolve()
    output = output.expanduser().resolve()
    if not source.is_file():
        raise ScrubError("source does not exist")
    if source == output:
        raise ScrubError("source and output must differ")
    if output.suffix != ".gz":
        raise ScrubError("output must use a .gz suffix")
    if _inside_repo(output):
        raise ScrubError("refusing to write a scrubbed capture inside the repository")
    if output.exists():
        raise ScrubError("output already exists")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    analysis = analyze(source)
    selection = select_external(analysis, top_hosts)
    if rng is None:
        rng = secrets.SystemRandom()
    mapping = build_mappings(analysis, selection, rng)
    if timestamp_delta is None:
        assert analysis.min_timestamp is not None
        target_start = rng.uniform(1_420_070_400.0, 1_735_689_600.0)
        timestamp_delta = target_start - analysis.min_timestamp
    fd, raw_candidate = tempfile.mkstemp(
        prefix=f".{output.stem}.", suffix=".gz", dir=output.parent
    )
    os.close(fd)
    candidate = Path(raw_candidate)
    try:
        rows_output, rows_tail = _write_candidate(
            source,
            candidate,
            analysis,
            selection,
            mapping,
            rng,
            timestamp_delta,
        )
        verified_rows, _ = verify_output(source, candidate)
        if verified_rows != rows_output:
            raise ScrubError("output verifier row count disagrees with writer")
        try:
            os.link(candidate, output)
        except FileExistsError as exc:
            raise ScrubError("output appeared while the scrub was running") from exc
    finally:
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass
    return ScrubReceipt(
        rows_input=analysis.rows_input,
        rows_eligible=analysis.rows_eligible,
        rows_non_unicast=analysis.rows_non_unicast,
        rows_tail=rows_tail,
        rows_output=rows_output,
        external_identities_observed=len(
            set(analysis.source_external) | set(analysis.destination_external)
        ),
        retained_external_identities=len(selection.union),
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="raw Zeek conn JSON-lines file or gzip")
    parser.add_argument("output", type=Path, help="private output path outside the repository")
    parser.add_argument("--top-hosts", type=int, default=DEFAULT_TOP_HOSTS)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if "scrubbed" in args.source.name.lower():
            raise ScrubError("refusing a source whose name already claims it is scrubbed")
        receipt = scrub_file(args.source, args.output, top_hosts=args.top_hosts)
    except ScrubError as exc:
        print(f"scrub-conn: {exc}", file=sys.stderr)
        return 1
    print(
        "scrubbed subset: "
        f"input={receipt.rows_input} eligible={receipt.rows_eligible} "
        f"non_unicast_dropped={receipt.rows_non_unicast} "
        f"tail_dropped={receipt.rows_tail} output={receipt.rows_output}"
    )
    print(
        "pre-map external identities: "
        f"observed={receipt.external_identities_observed} "
        f"retained={receipt.retained_external_identities}/{receipt.external_capacity}; "
        "this retained pre-map subset is not a claim about the graph's post-map rendered top set"
    )
    print(
        "preserved traffic fingerprint: ports, byte volumes, durations, states, "
        "relative timing, and two internal /24 shapes"
    )
    print("privacy verifiers: sanctioned_ranges=pass input_output_intersection=zero")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
