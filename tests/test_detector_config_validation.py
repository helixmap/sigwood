"""Shared regression contract for AWS, DNS, and Scan config validation."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
from types import ModuleType

import pytest

from sigwood import cli
from sigwood.common import config as config_module
from sigwood.detectors import aws, beacon, dns, scan


_MODULES: dict[str, ModuleType] = {"aws": aws, "dns": dns, "scan": scan}


def _config_with(detector: str, key: str, value: object) -> dict:
    config = copy.deepcopy(_MODULES[detector].DEFAULT_CONFIG)
    if key.startswith("pihole."):
        config["pihole"][key.removeprefix("pihole.")] = value
    else:
        config[key] = value
    return config


def _validate(detector: str, key: str, value: object) -> None:
    _MODULES[detector].validate_config(_config_with(detector, key, value))


_REJECTION_CASES = [
    ("aws", "min_events", "[detectors.aws].min_events", "positive integer"),
    (
        "aws",
        "min_scorable_principals",
        "[detectors.aws].min_scorable_principals",
        "positive integer",
    ),
    (
        "aws",
        "burst_gap_seconds",
        "[detectors.aws].burst_gap_seconds",
        "positive integer",
    ),
    (
        "aws",
        "burst_window_edge_margin_seconds",
        "[detectors.aws].burst_window_edge_margin_seconds",
        "non-negative integer",
    ),
    (
        "aws",
        "burst_min_firsts",
        "[detectors.aws].burst_min_firsts",
        "greater than or equal to 2",
    ),
    (
        "aws",
        "burst_high_error_rate",
        "[detectors.aws].burst_high_error_rate",
        "finite number from 0 through 1",
    ),
    (
        "aws",
        "burst_high_service_count",
        "[detectors.aws].burst_high_service_count",
        "positive integer",
    ),
    (
        "aws",
        "composite_medium_threshold",
        "[detectors.aws].composite_medium_threshold",
        "finite number",
    ),
    (
        "aws",
        "composite_low_threshold",
        "[detectors.aws].composite_low_threshold",
        "finite number",
    ),
    (
        "dns",
        "min_cluster_size",
        "[detectors.dns].min_cluster_size",
        "greater than or equal to 2",
    ),
    ("dns", "min_samples", "[detectors.dns].min_samples", "positive integer"),
    ("dns", "threshold", "[detectors.dns].threshold", "finite number"),
    (
        "dns",
        "promote_below_gate",
        "[detectors.dns].promote_below_gate",
        "boolean",
    ),
    (
        "dns",
        "promote_min_subdomains",
        "[detectors.dns].promote_min_subdomains",
        "positive integer",
    ),
    (
        "dns",
        "promote_min_nxdomain_fraction",
        "[detectors.dns].promote_min_nxdomain_fraction",
        "finite number from 0 through 1",
    ),
    (
        "dns",
        "thresh_high_entropy",
        "[detectors.dns].thresh_high_entropy",
        "finite number",
    ),
    (
        "dns",
        "scan_dense_clusters",
        "[detectors.dns].scan_dense_clusters",
        "boolean",
    ),
    (
        "dns",
        "scan_min_high_entropy_fraction",
        "[detectors.dns].scan_min_high_entropy_fraction",
        "finite number from 0 through 1",
    ),
    (
        "dns",
        "scan_min_cluster_members",
        "[detectors.dns].scan_min_cluster_members",
        "positive integer",
    ),
    (
        "dns",
        "scan_min_regdomain_share",
        "[detectors.dns].scan_min_regdomain_share",
        "finite number from 0 through 1",
    ),
    (
        "dns",
        "scan_max_members_per_cluster",
        "[detectors.dns].scan_max_members_per_cluster",
        "positive integer",
    ),
    (
        "dns",
        "pihole.min_cluster_size",
        "[detectors.dns.pihole].min_cluster_size",
        "greater than or equal to 2",
    ),
    (
        "dns",
        "pihole.min_samples",
        "[detectors.dns.pihole].min_samples",
        "positive integer",
    ),
    (
        "scan",
        "vertical_threshold",
        "[detectors.scan].vertical_threshold",
        "positive integer",
    ),
    (
        "scan",
        "horizontal_threshold",
        "[detectors.scan].horizontal_threshold",
        "positive integer",
    ),
    (
        "scan",
        "block_port_threshold",
        "[detectors.scan].block_port_threshold",
        "positive integer",
    ),
    (
        "scan",
        "block_host_threshold",
        "[detectors.scan].block_host_threshold",
        "positive integer",
    ),
    (
        "scan",
        "block_state_min",
        "[detectors.scan].block_state_min",
        "finite number from 0 through 1",
    ),
    (
        "scan",
        "slow_state_min",
        "[detectors.scan].slow_state_min",
        "finite number from 0 through 1",
    ),
    (
        "scan",
        "window_secs",
        "[detectors.scan].window_secs",
        "positive integer",
    ),
    (
        "scan",
        "slow_min_ports",
        "[detectors.scan].slow_min_ports",
        "positive integer",
    ),
    (
        "scan",
        "slow_min_buckets",
        "[detectors.scan].slow_min_buckets",
        "positive integer",
    ),
]


def _default_key_population() -> set[tuple[str, str]]:
    population: set[tuple[str, str]] = set()
    for detector, module in _MODULES.items():
        for key, value in module.DEFAULT_CONFIG.items():
            if detector == "dns" and key == "pihole":
                population.update((detector, f"pihole.{nested}") for nested in value)
            else:
                population.add((detector, key))
    return population


def test_rejection_cases_cover_every_default_key() -> None:
    assert {(detector, key) for detector, key, _path, _shape in _REJECTION_CASES} == (
        _default_key_population()
    )


@pytest.mark.parametrize(
    ("detector", "key", "path", "shape"),
    _REJECTION_CASES,
    ids=[f"{detector}-{key}" for detector, key, _path, _shape in _REJECTION_CASES],
)
def test_every_default_key_rejects_a_bad_value_without_echo(
    detector: str, key: str, path: str, shape: str,
) -> None:
    rejected = f"__rejected_{detector}_{key.replace('.', '_')}__"
    with pytest.raises(ValueError) as caught:
        _validate(detector, key, rejected)

    message = str(caught.value)
    assert path in message
    assert shape in message
    assert rejected not in message


@pytest.mark.parametrize("detector", ["aws", "dns", "scan"])
def test_default_config_validates_clean(detector: str) -> None:
    _MODULES[detector].validate_config(copy.deepcopy(_MODULES[detector].DEFAULT_CONFIG))


_NUMERIC_KEYS = [
    (detector, key)
    for detector, key, _path, shape in _REJECTION_CASES
    if shape != "boolean"
]


@pytest.mark.parametrize(
    ("detector", "key"),
    _NUMERIC_KEYS,
    ids=[f"{detector}-{key}" for detector, key in _NUMERIC_KEYS],
)
def test_bool_is_rejected_for_every_numeric_key(detector: str, key: str) -> None:
    with pytest.raises(ValueError):
        _validate(detector, key, True)


_POSITIVE_INTEGER_KEYS = [
    ("aws", "min_events"),
    ("aws", "min_scorable_principals"),
    ("aws", "burst_gap_seconds"),
    ("aws", "burst_high_service_count"),
    ("dns", "min_samples"),
    ("dns", "promote_min_subdomains"),
    ("dns", "scan_min_cluster_members"),
    ("dns", "scan_max_members_per_cluster"),
    ("dns", "pihole.min_samples"),
    ("scan", "vertical_threshold"),
    ("scan", "horizontal_threshold"),
    ("scan", "block_port_threshold"),
    ("scan", "block_host_threshold"),
    ("scan", "window_secs"),
    ("scan", "slow_min_ports"),
    ("scan", "slow_min_buckets"),
]


@pytest.mark.parametrize(("detector", "key"), _POSITIVE_INTEGER_KEYS)
def test_positive_integer_boundaries(detector: str, key: str) -> None:
    with pytest.raises(ValueError):
        _validate(detector, key, 0)
    _validate(detector, key, 1)


def test_special_integer_boundaries() -> None:
    aws.validate_config({**aws.DEFAULT_CONFIG, "burst_window_edge_margin_seconds": 0})
    with pytest.raises(ValueError):
        _validate("aws", "burst_window_edge_margin_seconds", -1)

    with pytest.raises(ValueError):
        _validate("aws", "burst_min_firsts", 1)
    _validate("aws", "burst_min_firsts", 2)

    for key in ("min_cluster_size", "pihole.min_cluster_size"):
        with pytest.raises(ValueError):
            _validate("dns", key, 1)
        _validate("dns", key, 2)


_FRACTION_KEYS = [
    ("aws", "burst_high_error_rate"),
    ("dns", "promote_min_nxdomain_fraction"),
    ("dns", "scan_min_high_entropy_fraction"),
    ("dns", "scan_min_regdomain_share"),
    ("scan", "block_state_min"),
    ("scan", "slow_state_min"),
]


@pytest.mark.parametrize(("detector", "key"), _FRACTION_KEYS)
@pytest.mark.parametrize("boundary", [0, 1])
def test_fraction_endpoints_are_accepted(
    detector: str, key: str, boundary: int,
) -> None:
    _validate(detector, key, boundary)


_REAL_KEYS = [
    ("aws", "burst_high_error_rate"),
    ("aws", "composite_medium_threshold"),
    ("aws", "composite_low_threshold"),
    ("dns", "threshold"),
    ("dns", "promote_min_nxdomain_fraction"),
    ("dns", "thresh_high_entropy"),
    ("dns", "scan_min_high_entropy_fraction"),
    ("dns", "scan_min_regdomain_share"),
    ("scan", "block_state_min"),
    ("scan", "slow_state_min"),
]


@pytest.mark.parametrize(("detector", "key"), _REAL_KEYS)
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_real_number_keys_reject_nonfinite_values(
    detector: str, key: str, value: float,
) -> None:
    with pytest.raises(ValueError):
        _validate(detector, key, value)


def test_unbounded_real_keys_accept_negative_finite_values() -> None:
    aws.validate_config({
        **aws.DEFAULT_CONFIG,
        "composite_medium_threshold": -1.0,
        "composite_low_threshold": -2.0,
    })
    dns.validate_config({
        **dns.DEFAULT_CONFIG,
        "threshold": -10.0,
        "thresh_high_entropy": -20.0,
    })


def test_aws_band_ordering_accepts_equality_and_rejects_inversion_without_echo() -> None:
    aws.validate_config({
        **aws.DEFAULT_CONFIG,
        "composite_medium_threshold": -7.25,
        "composite_low_threshold": -7.25,
    })

    medium = 123456.75
    low = 234567.5
    with pytest.raises(ValueError) as caught:
        aws.validate_config({
            **aws.DEFAULT_CONFIG,
            "composite_medium_threshold": medium,
            "composite_low_threshold": low,
        })
    message = str(caught.value)
    assert "[detectors.aws].composite_low_threshold" in message
    assert "less than or equal to [detectors.aws].composite_medium_threshold" in message
    assert str(medium) not in message
    assert str(low) not in message


@pytest.mark.parametrize("detector", ["aws", "dns", "scan"])
def test_unknown_top_level_key_is_ignored_and_validation_is_pure(
    detector: str,
) -> None:
    config = copy.deepcopy(_MODULES[detector].DEFAULT_CONFIG)
    config["future_key"] = {"preserve": []}
    before = copy.deepcopy(config)

    _MODULES[detector].validate_config(config)

    assert config == before


def test_unknown_nested_dns_key_is_ignored_and_validation_is_pure() -> None:
    config = copy.deepcopy(dns.DEFAULT_CONFIG)
    config["pihole"]["future_key"] = {"preserve": []}
    before = copy.deepcopy(config)

    dns.validate_config(config)

    assert config == before


@pytest.mark.parametrize(
    ("module", "path"),
    [
        (aws, "[detectors.aws]"),
        (dns, "[detectors.dns]"),
        (scan, "[detectors.scan]"),
    ],
)
def test_top_level_detector_section_must_be_a_table(
    module: ModuleType, path: str,
) -> None:
    with pytest.raises(ValueError, match=rf"^{re.escape(path)} must be a table$"):
        module.validate_config([])


def test_dns_pihole_section_must_be_a_table() -> None:
    with pytest.raises(
        ValueError, match=r"^\[detectors\.dns\]\.pihole must be a table$"
    ):
        dns.validate_config({**dns.DEFAULT_CONFIG, "pihole": []})


def test_real_cli_invalid_scan_section_is_actionable_and_sibling_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The real CLI contains Scan's bad section without stopping Beacon."""
    monkeypatch.setattr(config_module, "SEARCH_PATHS", [])
    sibling = {"ran": False}
    real_beacon_run = beacon.run

    def observe_beacon_run(context):
        sibling["ran"] = True
        return real_beacon_run(context)

    monkeypatch.setattr(beacon, "run", observe_beacon_run)
    conn = tmp_path / "conn.log"
    rows = [
        {
            "_path": "conn",
            "ts": 1_750_000_000.0 + i * 60,
            "uid": f"C{i:04d}",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 40_000 + i,
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 100,
            "resp_bytes": 200,
            "duration": 0.1,
            "local_orig": True,
        }
        for i in range(40)
    ]
    conn.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )
    config = tmp_path / "config.toml"
    config.write_text(
        "[sigwood]\n"
        'root = ""\n'
        'default_window = "all"\n'
        'home_net = ["192.0.2.0/24"]\n'
        "[detectors.scan]\n"
        'window_secs = "3600"\n',
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as caught:
        cli.main([
            "hunt",
            str(conn),
            "--detect=scan,beacon",
            f"--config={config}",
            "--no-allowlist",
            "-q",
        ])

    assert caught.value.code == 1
    captured = capsys.readouterr()
    reason = (
        "prep error - [detectors.scan].window_secs must be a positive integer"
    )
    report_words = " ".join(captured.out.split())
    assert f"scan - {reason}" in report_words
    assert "ufunc 'greater' did not contain a loop" not in captured.out
    assert sibling["ran"] is True
    assert f"scan: {reason}" in captured.err
    assert "Traceback" not in captured.err
