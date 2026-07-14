#!/usr/bin/env python3
"""Validate the release archives produced by ``python -m build``.

This is intentionally a standard-library-only check so the same command works in
CI and in the maintainer's release environment after ``build`` has completed.
It validates archive shape; installing and exercising the wheel remains a
separate smoke test because that belongs in a clean virtual environment.
"""

from __future__ import annotations

import argparse
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


WHEEL_RE = re.compile(r"^sigwood-(?P<version>[^-]+)-py3-none-any\.whl$")
SDIST_RE = re.compile(r"^sigwood-(?P<version>[^-]+)\.tar\.gz$")

REQUIRED_WHEEL_FILES = {
    "sigwood/__init__.py",
    "sigwood/data/config_example.toml",
    "sigwood/data/allowlist/connections",
    "sigwood/data/allowlist/domains_common",
    "sigwood/outputs/graph_player.html",
}

REQUIRED_SDIST_FILES = {
    "LICENSE",
    "README.md",
    "pyproject.toml",
    "sigwood/__init__.py",
    "sigwood/data/config_example.toml",
    "sigwood/outputs/graph_player.html",
}


def _single(dist_dir: Path, pattern: str, label: str) -> Path:
    matches = sorted(dist_dir.glob(pattern))
    if len(matches) != 1:
        names = ", ".join(path.name for path in matches) or "none"
        raise ValueError(f"expected exactly one {label}; found {names}")
    return matches[0]


def _assert_safe_member(name: str, archive: Path) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe path in {archive.name}: {name}")


def _archive_version(path: Path, pattern: re.Pattern[str], label: str) -> str:
    match = pattern.fullmatch(path.name)
    if match is None:
        raise ValueError(f"unexpected {label} filename: {path.name}")
    return match.group("version")


def validate_wheel(path: Path) -> str:
    version = _archive_version(path, WHEEL_RE, "wheel")
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())

        for name in names:
            _assert_safe_member(name, path)

        missing = sorted(REQUIRED_WHEEL_FILES - names)
        if missing:
            raise ValueError(f"wheel is missing required files: {', '.join(missing)}")

        leaked_tests = sorted(name for name in names if name.startswith("tests/"))
        if leaked_tests:
            raise ValueError(f"wheel unexpectedly contains tests: {leaked_tests[0]}")

        top_level = sorted(name for name in names if name.endswith(".dist-info/top_level.txt"))
        if len(top_level) != 1:
            raise ValueError("wheel must contain exactly one .dist-info/top_level.txt")
        contents = archive.read(top_level[0]).decode("utf-8").splitlines()
        if contents != ["sigwood"]:
            raise ValueError(f"unexpected wheel top-level packages: {contents!r}")

    return version


def validate_sdist(path: Path) -> str:
    version = _archive_version(path, SDIST_RE, "sdist")
    expected_root = f"sigwood-{version}"

    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}

        for name in names:
            _assert_safe_member(name, path)

        roots = {PurePosixPath(name).parts[0] for name in names if name}
        if roots != {expected_root}:
            raise ValueError(f"unexpected sdist roots: {sorted(roots)!r}")

        relative_names = {
            str(PurePosixPath(name).relative_to(expected_root))
            for name in names
            if name != expected_root
        }
        missing = sorted(REQUIRED_SDIST_FILES - relative_names)
        if missing:
            raise ValueError(f"sdist is missing required files: {', '.join(missing)}")

        leaked_tests = sorted(
            name
            for name in relative_names
            if name == "tests" or name.startswith("tests/") or name.endswith("/conftest.py")
        )
        if leaked_tests:
            raise ValueError(f"sdist unexpectedly contains tests: {leaked_tests[0]}")

    return version


def validate_distribution(dist_dir: Path) -> tuple[Path, Path, str]:
    if not dist_dir.is_dir():
        raise ValueError(f"distribution directory does not exist: {dist_dir}")

    wheel = _single(dist_dir, "*.whl", "wheel")
    sdist = _single(dist_dir, "*.tar.gz", "sdist")
    wheel_version = validate_wheel(wheel)
    sdist_version = validate_sdist(sdist)
    if wheel_version != sdist_version:
        raise ValueError(
            f"wheel/sdist version mismatch: {wheel_version!r} != {sdist_version!r}"
        )
    return wheel, sdist, wheel_version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "dist_dir",
        nargs="?",
        type=Path,
        default=Path("dist"),
        help="directory containing exactly one wheel and one sdist (default: dist)",
    )
    args = parser.parse_args()

    try:
        wheel, sdist, version = validate_distribution(args.dist_dir)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"distribution validation failed: {exc}\n")

    print(f"validated sigwood {version}: {wheel.name}, {sdist.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
