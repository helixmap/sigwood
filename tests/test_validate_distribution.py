"""Release archive validation and literal expected-version enforcement."""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parents[1]
_TOOL = _ROOT / "tools" / "validate_distribution.py"
_SPEC = importlib.util.spec_from_file_location("validate_distribution", _TOOL)
assert _SPEC is not None and _SPEC.loader is not None
validator = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(validator)


def _distribution(directory: Path, version: str, *, sdist_version: str | None = None) -> tuple[Path, Path]:
    """Create minimal archive shapes, without claiming an installable package."""
    directory.mkdir()
    wheel = directory / f"sigwood-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name in sorted(validator.REQUIRED_WHEEL_FILES):
            archive.writestr(name, b"synthetic\n")
        archive.writestr(f"sigwood-{version}.dist-info/top_level.txt", b"sigwood\n")
    source_version = version if sdist_version is None else sdist_version
    sdist = directory / f"sigwood-{source_version}.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name in sorted(validator.REQUIRED_SDIST_FILES):
            data = b"synthetic\n"
            member = tarfile.TarInfo(f"sigwood-{source_version}/{name}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return wheel, sdist


def _cli(directory: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_TOOL), str(directory), *args],
        capture_output=True, text=True, timeout=10,
    )


@pytest.mark.parametrize("version", ["1.2.3", "1.2.3.dev7"])
def test_distribution_without_expectation_retains_cli_and_helper_behavior(tmp_path: Path, version: str) -> None:
    directory = tmp_path / "dist"
    wheel, sdist = _distribution(directory, version)
    assert validator.validate_distribution(directory) == (wheel, sdist, version)
    result = _cli(directory)
    assert result.returncode == 0 and result.stderr == ""
    assert result.stdout == f"validated sigwood {version}: {wheel.name}, {sdist.name}\n"


def test_distribution_expected_version_matches_both_validated_archives(tmp_path: Path) -> None:
    directory = tmp_path / "dist"
    wheel, sdist = _distribution(directory, "1.2.3")
    assert validator.validate_distribution(directory, expect_version="1.2.3") == (wheel, sdist, "1.2.3")
    result = _cli(directory, "--expect-version", "1.2.3")
    assert result.returncode == 0 and result.stderr == ""
    assert result.stdout == f"validated sigwood 1.2.3: {wheel.name}, {sdist.name}\n"


def test_distribution_mismatch_fails_before_success_narration(tmp_path: Path) -> None:
    directory = tmp_path / "dist"
    _distribution(directory, "1.2.3")
    with pytest.raises(ValueError, match="distribution version '1.2.3'.*expected version '1.2.4'"):
        validator.validate_distribution(directory, expect_version="1.2.4")
    result = _cli(directory, "--expect-version", "1.2.4")
    assert result.returncode == 1 and result.stdout == ""
    assert result.stderr == "distribution validation failed: distribution version '1.2.3' does not match expected version '1.2.4'\n"


def test_distribution_still_refuses_wheel_sdist_disagreement(tmp_path: Path) -> None:
    directory = tmp_path / "dist"
    _distribution(directory, "1.2.3", sdist_version="1.2.4")
    result = _cli(directory, "--expect-version", "1.2.3")
    assert result.returncode == 1 and result.stdout == ""
    assert "wheel/sdist version mismatch" in result.stderr
    assert "expected version" not in result.stderr


def test_expected_version_is_literal_without_tag_prefix_normalization(tmp_path: Path) -> None:
    directory = tmp_path / "dist"
    _distribution(directory, "1.2.3")
    result = _cli(directory, "--expect-version", "v1.2.3")
    assert result.returncode == 1 and result.stdout == ""
    assert "expected version 'v1.2.3'" in result.stderr


def test_expected_version_option_requires_a_value(tmp_path: Path) -> None:
    directory = tmp_path / "dist"
    _distribution(directory, "1.2.3")
    result = _cli(directory, "--expect-version")
    assert result.returncode == 2 and result.stdout == ""
    assert "expected one argument" in result.stderr


@pytest.mark.parametrize("expected", ["1.2.4\n::error::forged\r\x1b[31m\x7f\x85\x9b", "1.2.4\udc9b"])
def test_expected_version_mismatch_escapes_untrusted_text(tmp_path: Path, expected: str) -> None:
    directory = tmp_path / "dist"
    _distribution(directory, "1.2.3")
    result = _cli(directory, "--expect-version", expected)
    assert result.returncode == 1 and result.stdout == ""
    assert result.stderr.count("\n") == 1
    assert not any((ord(c) < 32 and c != "\n") or 127 <= ord(c) < 160 or 0xDC80 <= ord(c) < 0xDD00 for c in result.stderr)
    assert "does not match expected version" in result.stderr
    assert "Traceback" not in result.stderr
