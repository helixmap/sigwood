"""End-to-end tests for the private syslog rare-population measurement tool."""

from __future__ import annotations

import json
from pathlib import Path

from sigwood import runner
from sigwood.common import config as cfg
from tools import measure_syslog_rare_population as measure


_EVENT_TS = 1_784_376_000.0


def _syslog_line(
    host: str,
    message: str,
    *,
    program: str = "app",
    pid: int = 101,
) -> str:
    return f"Jul 21 12:00:00 {host} {program}[{pid}]: {message}"


def _zeek_record(line: str, *, uid: str, ts: float = _EVENT_TS) -> dict[str, object]:
    return {
        "_path": "syslog",
        "ts": ts,
        "uid": uid,
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 40001,
        "id.resp_h": "198.51.100.20",
        "id.resp_p": 514,
        "proto": "udp",
        "facility": "DAEMON",
        "severity": "INFO",
        "message": line,
    }


def _config(tmp_path: Path, *, max_count: int = 1) -> dict:
    config_file = tmp_path / "freeze.toml"
    config_file.write_text(
        "\n".join((
            "[sigwood]",
            f'root = "{tmp_path}"',
            'default_window = ""',
            'syslog_source = "files"',
            "warn_above = 0",
            "",
            "[allowlist]",
            "enabled = true",
            "",
            "[detectors.syslog]",
            f"max_count = {max_count}",
            "",
        )),
        encoding="utf-8",
    )
    return cfg.load(config_file)


def _flat_dir(tmp_path: Path, lines: list[str]) -> Path:
    directory = tmp_path / "flat"
    directory.mkdir(parents=True)
    (directory / "system.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return directory


def _zeek_dir(tmp_path: Path, lines: list[str]) -> Path:
    directory = tmp_path / "zeek"
    directory.mkdir(parents=True)
    records = [
        _zeek_record(line, uid=f"C{index}", ts=_EVENT_TS + index)
        for index, line in enumerate(lines)
    ]
    (directory / "syslog.log").write_text(
        "".join(json.dumps(row) + "\n" for row in records), encoding="utf-8"
    )
    return directory


def _measure(
    config: dict,
    *,
    flat: Path | None = None,
    zeek: Path | None = None,
    no_allowlist: bool = False,
) -> int:
    return measure.observe_rare_non_reboot_rows(
        config,
        syslog_dir=flat,
        zeek_dir=zeek,
        since=None,
        until=None,
        load_all=True,
        no_allowlist=no_allowlist,
    )


def _finding_contract(payload: dict) -> list[tuple[object, object, object, object]]:
    return [
        (
            finding["severity"],
            finding["evidence"].get("tier"),
            finding["title"],
            finding["evidence"],
        )
        for finding in payload["findings"]
    ]


def _product_payload(config: dict, flat: Path) -> dict:
    report = flat.parent / "product.json"
    assert runner.run(
        config,
        detect="syslog",
        syslog_dir=flat,
        scope=frozenset({"syslog_dir"}),
        output_format="json",
        output_file=report,
        load_all=True,
        quiet=True,
        syslog_source="files",
    ) == 0
    return json.loads(report.read_text(encoding="utf-8"))


def test_measurement_observes_runner_allowlist_on_and_off(tmp_path: Path) -> None:
    hosts = tmp_path / "allowlist.d"
    hosts.mkdir()
    (hosts / "hosts_test").write_text("hidden-host\n", encoding="utf-8")
    flat = _flat_dir(tmp_path, [
        _syslog_line("visible-host", "visible alpha beta gamma delta"),
        _syslog_line("hidden-host", "hidden epsilon zeta eta theta"),
    ])

    assert _measure(_config(tmp_path), flat=flat) == 1
    assert _measure(_config(tmp_path), flat=flat, no_allowlist=True) == 2


def test_measurement_uses_shipped_drain3_hex_pair_mask(tmp_path: Path) -> None:
    flat = _flat_dir(tmp_path, [
        _syslog_line("host-a", "marker aa bb cc dd ee ff"),
        _syslog_line("host-b", "marker 11 22 33 44 55 66", pid=102),
    ])

    assert _measure(_config(tmp_path), flat=flat) == 0


def test_measurement_excludes_reboot_rows_with_shared_grammar(tmp_path: Path) -> None:
    flat = _flat_dir(tmp_path, [
        _syslog_line(
            "host-a", "System is rebooting.", program="systemd-logind"
        ),
        _syslog_line("host-a", "ordinary singleton", pid=102),
    ])

    assert _measure(_config(tmp_path), flat=flat) == 1


def test_measurement_uses_frozen_detector_configuration(tmp_path: Path) -> None:
    flat = _flat_dir(tmp_path, [
        _syslog_line("host-a", "repeated shape"),
        _syslog_line("host-b", "repeated shape", pid=102),
    ])

    assert _measure(_config(tmp_path, max_count=1), flat=flat) == 0
    assert _measure(_config(tmp_path, max_count=2), flat=flat) == 2


def test_measurement_routes_flat_zeek_and_mixed_through_runner(tmp_path: Path) -> None:
    flat_only = _flat_dir(
        tmp_path / "flat-only", [_syslog_line("flat-host", "flat once")]
    )
    zeek_only = _zeek_dir(
        tmp_path / "zeek-only", [_syslog_line("zeek-host", "zeek once")]
    )
    mixed_root = tmp_path / "mixed"
    mixed_flat = _flat_dir(
        mixed_root,
        [_syslog_line("shared-host", "shared alpha beta gamma delta")],
    )
    mixed_zeek = _zeek_dir(
        mixed_root,
        [
            _syslog_line("shared-host", "shared alpha beta gamma delta"),
            _syslog_line("zeek-host", "zeek epsilon zeta eta theta", pid=102),
        ],
    )

    assert _measure(_config(flat_only.parent), flat=flat_only) == 1
    assert _measure(_config(zeek_only.parent), zeek=zeek_only) == 1
    assert _measure(_config(mixed_root), flat=mixed_flat, zeek=mixed_zeek) == 2


def test_observation_preserves_the_complete_product_finding_contract(tmp_path: Path) -> None:
    flat = _flat_dir(tmp_path, [
        _syslog_line("host-a", "first alpha beta gamma delta"),
        _syslog_line("host-a", "second epsilon zeta eta theta", pid=102),
    ])
    config = _config(tmp_path)

    before = _finding_contract(_product_payload(config, flat))
    assert _measure(config, flat=flat) == 2
    after = _finding_contract(_product_payload(config, flat))

    assert after == before


def test_cli_prints_one_aggregate_and_uses_a_temporary_report_sink(
    tmp_path: Path, capsys,
) -> None:
    flat = _flat_dir(tmp_path, [_syslog_line("host-a", "one observation")])
    config_file = tmp_path / "freeze.toml"
    _config(tmp_path)

    assert measure.main([
        "--config", str(config_file), "--syslog-dir", str(flat), "--all",
    ]) == 0

    captured = capsys.readouterr()
    assert captured.out == "rare_non_reboot_rows=1\n"
    assert not (tmp_path / "discarded-run.json").exists()


def test_cli_preserves_safe_usage_errors_and_hides_config_paths(
    tmp_path: Path, capsys,
) -> None:
    config_file = tmp_path / "freeze.toml"
    _config(tmp_path)

    assert measure.main(["--config", str(config_file)]) == 2
    assert capsys.readouterr().err == (
        "measure-syslog-rare-population: a source is required\n"
    )

    missing = tmp_path / "not-present.toml"
    assert measure.main([
        "--config", str(missing), "--syslog-dir", str(tmp_path),
    ]) == 2
    error = capsys.readouterr().err
    assert error == "measure-syslog-rare-population: could not read the config\n"
    assert str(missing) not in error
