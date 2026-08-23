#!/usr/bin/env python3
"""Rebase a site config onto sigwood's current shipped config spine.

The operation is a three-way text merge:

    current site config + last conformed spine + current shipped example

The spine is a credential-free copy of the shipped example from the last
successful conformance.  It lets Git distinguish local edits and additions
from later distro changes without ever copying site secrets into the tree.

Checking is the default and never writes.  ``--write`` creates a private,
timestamped byte-for-byte backup, atomically installs a clean merge, validates
the read-back, and only then advances the spine.  A conflict changes nothing.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_CONFIG = Path("~/.sigwood/config.toml").expanduser()
DEFAULT_SPINE = Path("~/.sigwood/config.spine.toml").expanduser()
SHIPPED_DEFAULT = (
    Path(__file__).resolve().parents[1] / "sigwood" / "data" / "config_example.toml"
)


class ConformError(ValueError):
    """An actionable conformance failure safe to show on stderr."""


@dataclass(frozen=True)
class MergeResult:
    data: bytes
    conflicted: bool


def _validate_toml(data: bytes, label: str) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConformError(f"{label} is not UTF-8: {exc}") from exc
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConformError(f"{label} is not valid TOML: {exc}") from exc


def _read_toml(path: Path, label: str) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConformError(f"cannot read {label} {path}: {exc}") from exc
    _validate_toml(data, label)
    return data


def merge_bytes(
    current: bytes,
    spine: bytes,
    shipped: bytes,
    *,
    git: str = "git",
) -> MergeResult:
    """Return Git's three-way merge without mutating any caller-owned file."""

    _validate_toml(current, "current config")
    _validate_toml(spine, "saved spine")
    _validate_toml(shipped, "shipped default")

    executable = shutil.which(git)
    if executable is None:
        raise ConformError(f"cannot find merge helper: {git}")

    with tempfile.TemporaryDirectory(prefix="sigwood-config-conform-") as tmp:
        root = Path(tmp)
        current_path = root / "current.toml"
        spine_path = root / "spine.toml"
        shipped_path = root / "shipped.toml"
        current_path.write_bytes(current)
        spine_path.write_bytes(spine)
        shipped_path.write_bytes(shipped)

        process = subprocess.run(
            [
                executable,
                "merge-file",
                "--stdout",
                "-L",
                "current site config",
                "-L",
                "last conformed spine",
                "-L",
                "current shipped default",
                str(current_path),
                str(spine_path),
                str(shipped_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    if process.returncode not in (0, 1):
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise ConformError(f"three-way merge failed: {detail or 'git merge-file error'}")
    if process.returncode == 0:
        _validate_toml(process.stdout, "merged candidate")
    return MergeResult(process.stdout, conflicted=process.returncode == 1)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Privately write one complete file, then atomically replace the target."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, raw_temp = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temp = Path(raw_temp)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise


def _backup_path(config_path: Path, now: datetime) -> Path:
    stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = config_path.with_name(f"{config_path.name}.pre-conform-{stamp}.bak")
    if not candidate.exists():
        return candidate
    for index in range(1, 1000):
        numbered = candidate.with_name(f"{candidate.name}.{index}")
        if not numbered.exists():
            return numbered
    raise ConformError("could not allocate a unique config backup name")


def _write_output(path: Path, data: bytes) -> None:
    atomic_write(path, data)
    print(f"wrote private merge candidate: {path}")


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _require_distinct_paths(
    config_path: Path,
    spine_path: Path,
    shipped_path: Path,
    output: Path | None,
) -> None:
    named = {
        "current config": _resolved(config_path),
        "saved spine": _resolved(spine_path),
        "shipped default": _resolved(shipped_path),
    }
    if len(set(named.values())) != len(named):
        raise ConformError("config, spine, and shipped-default paths must be distinct")
    if output is not None and _resolved(output) in named.values():
        raise ConformError(
            "candidate output must not overwrite the config, spine, or shipped default"
        )


def seed_spine(spine_path: Path, shipped_path: Path) -> int:
    if _resolved(spine_path) == _resolved(shipped_path):
        raise ConformError("saved spine and shipped-default paths must be distinct")
    shipped = _read_toml(shipped_path, "shipped default")
    if spine_path.exists():
        existing = _read_toml(spine_path, "saved spine")
        if existing == shipped:
            print(f"config spine already seeded: {spine_path}")
            return 0
        raise ConformError(
            f"saved spine already exists and differs: {spine_path}; "
            "run a normal conformance instead of replacing merge history"
        )
    atomic_write(spine_path, shipped)
    if spine_path.read_bytes() != shipped:
        raise ConformError(f"saved spine read-back mismatch: {spine_path}")
    print(f"seeded credential-free config spine: {spine_path}")
    return 0


def conform(
    config_path: Path,
    spine_path: Path,
    shipped_path: Path,
    *,
    write: bool,
    output: Path | None,
    now: datetime | None = None,
) -> int:
    _require_distinct_paths(config_path, spine_path, shipped_path, output)
    current = _read_toml(config_path, "current config")
    shipped = _read_toml(shipped_path, "shipped default")
    if not spine_path.exists():
        raise ConformError(
            f"saved spine is absent: {spine_path}; after a reviewed conformance, "
            "initialize it once with --seed-spine"
        )
    spine = _read_toml(spine_path, "saved spine")

    if spine == shipped:
        print("config spine is current; no conformance needed")
        return 0

    merged = merge_bytes(current, spine, shipped)
    if merged.conflicted:
        if output is not None:
            _write_output(output, merged.data)
        raise ConformError(
            "config conformance has merge conflicts; the live config and saved spine "
            "were not changed"
        )

    if output is not None:
        _write_output(output, merged.data)

    if not write:
        state = "already matches the new spine" if merged.data == current else "has an update"
        print(f"config conformance {state}; rerun with --write after review")
        return 1

    backup: Path | None = None
    if merged.data != current:
        backup = _backup_path(config_path, now or datetime.now(timezone.utc))
        atomic_write(backup, current)
        if backup.read_bytes() != current:
            raise ConformError(f"config backup read-back mismatch: {backup}")
        atomic_write(config_path, merged.data)
        if config_path.read_bytes() != merged.data:
            raise ConformError(f"config read-back mismatch: {config_path}")

    # Advancing the spine last makes any partial failure recoverable: a stale
    # spine causes another merge; it never causes local edits to be forgotten.
    atomic_write(spine_path, shipped)
    if spine_path.read_bytes() != shipped:
        raise ConformError(f"saved spine read-back mismatch: {spine_path}")

    if backup is None:
        print(f"config content already conformed; advanced spine: {spine_path}")
    else:
        print(f"conformed config: {config_path}")
        print(f"preserved original bytes: {backup}")
        print(f"advanced credential-free spine: {spine_path}")
    return 0


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python tools/conform_config.py
  python tools/conform_config.py --output /tmp/config.candidate.toml
  python tools/conform_config.py --write

exit status: 0 = current/applied, 1 = clean update waiting, 2 = conflict/error
""",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--write",
        action="store_true",
        help="back up and atomically install a clean merge, then advance the spine",
    )
    action.add_argument(
        "--seed-spine",
        action="store_true",
        help="one-time initialization after a reviewed conformance; never writes config",
    )
    parser.add_argument("--config", type=_path, default=DEFAULT_CONFIG)
    parser.add_argument("--spine", type=_path, default=DEFAULT_SPINE)
    parser.add_argument("--default", dest="shipped", type=_path, default=SHIPPED_DEFAULT)
    parser.add_argument(
        "--output",
        type=_path,
        help="write a private candidate for review (including conflict markers if needed)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.seed_spine and args.output is not None:
        parser.error("--output cannot be combined with --seed-spine")
    try:
        if args.seed_spine:
            return seed_spine(args.spine, args.shipped)
        return conform(
            args.config,
            args.spine,
            args.shipped,
            write=args.write,
            output=args.output,
        )
    except (ConformError, OSError) as exc:
        parser.exit(2, f"config conformance failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
