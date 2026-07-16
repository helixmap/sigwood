"""System-log mode validation, migration provenance, and config-boundary tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from sigwood.common import config as cfg
from sigwood.common.syslog_mode import (
    ConfiguredSyslogMode,
    SyslogMode,
    SyslogModeError,
    classify_configured_syslog_mode,
    parse_syslog_mode,
)


@pytest.mark.parametrize("mode", list(SyslogMode))
def test_parse_syslog_mode_accepts_exact_wire_values(mode: SyslogMode) -> None:
    assert parse_syslog_mode(mode.value) is mode
    assert parse_syslog_mode(mode) is mode


@pytest.mark.parametrize(
    "value", ["AUTO", " auto", "auto ", "journald", "", None, 1, True]
)
def test_parse_syslog_mode_rejects_coercion_and_non_enum_values(value: object) -> None:
    with pytest.raises(SyslogModeError, match="syslog_source must be one of"):
        parse_syslog_mode(value)


@pytest.mark.parametrize(
    (
        "mode_present",
        "mode_value",
        "dir_present",
        "dir_value",
        "disk_shape",
        "expected",
    ),
    [
        (True, "journal", True, "/logs", True, ConfiguredSyslogMode(SyslogMode.JOURNAL, False)),
        (False, "auto", True, "", True, ConfiguredSyslogMode(SyslogMode.OFF, False)),
        (False, "auto", True, "/logs", True, ConfiguredSyslogMode(SyslogMode.AUTO, True)),
        (False, "auto", False, "/merged", True, ConfiguredSyslogMode(SyslogMode.AUTO, True)),
        (True, "auto", True, "", False, ConfiguredSyslogMode(SyslogMode.AUTO, False)),
        (False, None, True, "/logs", False, ConfiguredSyslogMode(SyslogMode.FILES, False)),
        (False, None, True, "", False, ConfiguredSyslogMode(SyslogMode.OFF, False)),
        (False, None, False, None, False, ConfiguredSyslogMode(SyslogMode.OFF, False)),
    ],
)
def test_configured_mode_truth_table(
    mode_present: bool,
    mode_value: object,
    dir_present: bool,
    dir_value: object,
    disk_shape: bool,
    expected: ConfiguredSyslogMode,
) -> None:
    assert classify_configured_syslog_mode(
        mode_present=mode_present,
        mode_value=mode_value,
        dir_present=dir_present,
        dir_value=dir_value,
        disk_shape=disk_shape,
    ) == expected


def test_config_load_no_file_carries_auto_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    loaded = cfg.load()
    assert loaded["sigwood"]["syslog_source"] == "auto"
    assert "__user_set__" not in loaded


def test_config_load_rejects_invalid_syslog_source(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[sigwood]\nsyslog_source = "AUTO"\n', encoding="utf-8")
    with pytest.raises(
        cfg.ConfigError,
        match=r"\[sigwood\]\.syslog_source='AUTO' must be one of",
    ):
        cfg.load(path)


def test_syslog_mode_leaf_imports_no_project_or_heavy_modules() -> None:
    code = """
import sys
import sigwood.common.syslog_mode
blocked = sorted(
    name for name in sys.modules
    if name == "pandas" or name.startswith("sigwood.common.loader")
    or name in {"sigwood.common.config", "sigwood.common.sources", "sigwood.runner"}
)
print("\\n".join(blocked))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == ""
