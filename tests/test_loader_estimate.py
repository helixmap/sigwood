"""The pre-read estimate must never invent a size bound for compressed input."""

from __future__ import annotations

import bz2
import gzip
import json
import lzma
import random
from pathlib import Path

import pytest

from sigwood.common.loader import PatternPreview, estimate_population
from sigwood.common.loader.io import _open_log
from sigwood.common.loader.pipeline import _sample_line_counts
from sigwood.common.loader import pipeline


def _preview(path: Path) -> dict[str, PatternPreview]:
    return {"syslog*.log*": PatternPreview("syslog_dir", (path,), (path,))}


def test_exact_count_agrees_with_text_reader_on_byte_strings(tmp_path: Path) -> None:
    rng = random.Random(8342)
    alphabet = [0, 10, 13, 32, 65, 127, 128, 195, 169, 255]
    for length in range(100):
        path = tmp_path / "fixture.log"
        path.write_bytes(bytes(rng.choice(alphabet) for _ in range(length)))
        expected = sum(1 for _ in _open_log(path))
        assert _sample_line_counts(path.read_bytes(), eof=True)[0] == expected
        estimate = estimate_population(_preview(path))["syslog*.log*"]
        assert estimate.records == expected
        assert estimate.records_basis == "exact"
        assert estimate.upper_bound_bytes == length


def test_compressed_input_has_no_decompressed_bound(tmp_path: Path) -> None:
    for payload in (b"a", b"a\n" * 1000 + b"b\n" * 1000):
        path = tmp_path / "fixture.log.gz"
        path.write_bytes(gzip.compress(payload))
        estimate = estimate_population(_preview(path))["syslog*.log*"]
        assert estimate.upper_bound_bytes is None
        assert estimate.records == len(payload.splitlines())


def test_concatenated_gzip_and_one_byte_sample_remain_unbounded(tmp_path: Path) -> None:
    path = tmp_path / "rotated.log.gz"
    path.write_bytes(gzip.compress(b"one\r\ntwo\r") + gzip.compress(b"three\n"))
    exact = estimate_population(_preview(path))["syslog*.log*"]
    assert exact.records == sum(1 for _ in _open_log(path))
    assert exact.records_basis == "exact"
    assert exact.upper_bound_bytes is None

    sampled = estimate_population(_preview(path), sample_bytes=1)["syslog*.log*"]
    assert sampled.records_basis == "estimated"
    assert sampled.upper_bound_bytes is None


def test_bounded_multibyte_sample_uses_bytes_for_density(tmp_path: Path) -> None:
    path = tmp_path / "fixture.log"
    path.write_bytes(("éééé\n" * 100).encode())
    estimate = estimate_population(_preview(path), sample_bytes=18)["syslog*.log*"]
    assert estimate.records_basis == "estimated"
    assert estimate.records == 100


def test_gzip_estimate_excludes_decompressor_read_ahead(tmp_path: Path) -> None:
    rng = random.Random(31)
    path = tmp_path / "many.log.gz"
    payload = "".join(
        f"{index:05d} {rng.getrandbits(64):016x} {rng.getrandbits(64):016x}\n"
        for index in range(50_000)
    ).encode()
    path.write_bytes(gzip.compress(payload))
    estimate = estimate_population(_preview(path))["syslog*.log*"]
    assert estimate.records_basis == "estimated"
    assert abs(estimate.records - 50_000) / 50_000 < 0.1


@pytest.mark.parametrize("suffix,compress", [
    (".bz2", bz2.compress), (".xz", lzma.compress),
])
def test_other_compressed_samples_remain_advisory_and_unbounded(
    tmp_path: Path, suffix, compress,
) -> None:
    path = tmp_path / f"many.log{suffix}"
    path.write_bytes(compress(b"line\n" * 20_000))
    estimate = estimate_population(_preview(path))["syslog*.log*"]
    assert estimate.records_basis == "estimated"
    assert estimate.upper_bound_bytes is None
    assert estimate.records > 0


def test_cloudtrail_unknown_is_not_called_a_lower_bound(tmp_path: Path) -> None:
    path = tmp_path / "delivery.json.gz"
    path.write_bytes(gzip.compress(json.dumps({"Records": [{"eventName": "x"}] * 30}).encode()))
    preview = {"*.json.gz": PatternPreview("cloudtrail_dir", (path,), (path,))}
    short = estimate_population(preview, sample_bytes=30)["*.json.gz"]
    assert short.records == 0
    assert short.records_basis == "estimated"
    assert short.uncounted_files == 1
    assert short.upper_bound_bytes is None
    complete = estimate_population(preview, sample_bytes=65536)["*.json.gz"]
    assert complete.records == 30
    assert complete.records_basis == "exact"
    assert complete.uncounted_files == 0


def test_sampling_caps_files_and_decompressed_bytes(tmp_path: Path, monkeypatch) -> None:
    paths = tuple(tmp_path / f"{index:02d}.log.gz" for index in range(35))
    for path in paths:
        path.write_bytes(gzip.compress(b"line\n" * 100))

    opened: list[Path] = []
    original = pipeline._loader._open_log_bytes

    class BoundedStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size):
            assert 0 < size <= 13
            data = self.stream.read(size)
            assert len(data) <= 13
            return data

    def watched(path, *, raw=None):
        opened.append(path)
        return BoundedStream(original(path, raw=raw))

    monkeypatch.setattr(pipeline._loader, "_open_log_bytes", watched)
    preview = PatternPreview("syslog_dir", paths, paths)
    result = estimate_population({"syslog*.log*": preview}, sample_files=3,
                                 sample_bytes=13)["syslog*.log*"]
    assert len(opened) == 3
    assert result.upper_bound_bytes is None
    assert result.records_basis == "estimated"


def test_unsampled_gzip_rotations_use_sampled_compression_ratio(tmp_path: Path) -> None:
    payload = b"host program message\n" * 400
    compressed = gzip.compress(payload)
    paths = tuple(tmp_path / f"rotation-{index}.log.gz" for index in range(5))
    for path in paths:
        path.write_bytes(compressed)
    preview = PatternPreview("syslog_dir", paths, paths)
    result = estimate_population({"*.log*": preview}, sample_files=1)["*.log*"]
    assert result.records == 2_000
    assert result.records_basis == "estimated"
    assert result.uncounted_files == 0
    assert result.upper_bound_bytes is None

    unknown = estimate_population({"*.log*": preview}, sample_files=0)["*.log*"]
    assert unknown.uncounted_files == 5
