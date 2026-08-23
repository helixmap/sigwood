"""The maintainer config-conformance fixture preserves site edits safely."""

from __future__ import annotations

import importlib.util
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "config_conform"
SPEC = importlib.util.spec_from_file_location(
    "conform_config_tool", ROOT / "tools" / "conform_config.py"
)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_three_way_fixture_preserves_site_edits_and_new_spine() -> None:
    result = tool.merge_bytes(
        _fixture("local.toml"),
        _fixture("base.toml"),
        _fixture("upstream.toml"),
    )

    assert result.conflicted is False
    assert result.data == _fixture("expected.toml")


def test_conflict_is_returned_without_fabricating_valid_toml() -> None:
    base = b'[sigwood]\ndetect = "default"\n'
    local = b'[sigwood]\ndetect = "site"\n'
    upstream = b'[sigwood]\ndetect = "new-default"\n'

    result = tool.merge_bytes(local, base, upstream)

    assert result.conflicted is True
    assert b"<<<<<<< current site config" in result.data
    assert b">>>>>>> current shipped default" in result.data


def test_seed_is_private_and_refuses_to_replace_history(tmp_path: Path) -> None:
    shipped = tmp_path / "shipped.toml"
    spine = tmp_path / "home" / "config.spine.toml"
    shipped.write_bytes(_fixture("base.toml"))

    assert tool.seed_spine(spine, shipped) == 0
    assert spine.read_bytes() == shipped.read_bytes()
    assert os.stat(spine).st_mode & 0o777 == 0o600

    shipped.write_bytes(_fixture("upstream.toml"))
    with pytest.raises(tool.ConformError, match="differs"):
        tool.seed_spine(spine, shipped)


def test_write_backs_up_installs_and_advances_spine(tmp_path: Path) -> None:
    config = tmp_path / "home" / "config.toml"
    spine = tmp_path / "home" / "config.spine.toml"
    shipped = tmp_path / "repo" / "config_example.toml"
    config.parent.mkdir()
    shipped.parent.mkdir()
    config.write_bytes(_fixture("local.toml"))
    spine.write_bytes(_fixture("base.toml"))
    shipped.write_bytes(_fixture("upstream.toml"))
    now = datetime(2026, 8, 22, 18, 30, tzinfo=timezone.utc)

    result = tool.conform(
        config,
        spine,
        shipped,
        write=True,
        output=None,
        now=now,
    )

    backup = config.with_name("config.toml.pre-conform-20260822T183000Z.bak")
    assert result == 0
    assert config.read_bytes() == _fixture("expected.toml")
    assert backup.read_bytes() == _fixture("local.toml")
    assert spine.read_bytes() == _fixture("upstream.toml")
    assert os.stat(config).st_mode & 0o777 == 0o600
    assert os.stat(backup).st_mode & 0o777 == 0o600
    assert os.stat(spine).st_mode & 0o777 == 0o600


def test_conflicted_write_changes_neither_config_nor_spine(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    spine = tmp_path / "spine.toml"
    shipped = tmp_path / "shipped.toml"
    base = b'[sigwood]\ndetect = "default"\n'
    config.write_bytes(b'[sigwood]\ndetect = "site"\n')
    spine.write_bytes(base)
    shipped.write_bytes(b'[sigwood]\ndetect = "new-default"\n')
    before_config = config.read_bytes()
    before_spine = spine.read_bytes()

    with pytest.raises(tool.ConformError, match="merge conflicts"):
        tool.conform(
            config,
            spine,
            shipped,
            write=True,
            output=None,
        )

    assert config.read_bytes() == before_config
    assert spine.read_bytes() == before_spine
    assert list(tmp_path.glob("*.bak")) == []


def test_check_reports_update_without_writing(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    spine = tmp_path / "spine.toml"
    shipped = tmp_path / "shipped.toml"
    config.write_bytes(_fixture("local.toml"))
    spine.write_bytes(_fixture("base.toml"))
    shipped.write_bytes(_fixture("upstream.toml"))
    before = (config.read_bytes(), spine.read_bytes(), shipped.read_bytes())

    result = tool.conform(
        config,
        spine,
        shipped,
        write=False,
        output=None,
    )

    assert result == 1
    assert (config.read_bytes(), spine.read_bytes(), shipped.read_bytes()) == before
    assert list(tmp_path.glob("*.bak")) == []


def test_candidate_output_cannot_replace_an_input(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    spine = tmp_path / "spine.toml"
    shipped = tmp_path / "shipped.toml"
    config.write_bytes(_fixture("local.toml"))
    spine.write_bytes(_fixture("base.toml"))
    shipped.write_bytes(_fixture("upstream.toml"))

    with pytest.raises(tool.ConformError, match="must not overwrite"):
        tool.conform(
            config,
            spine,
            shipped,
            write=False,
            output=config,
        )

    assert config.read_bytes() == _fixture("local.toml")
