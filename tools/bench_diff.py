#!/usr/bin/env python3
"""Compare two privacy-projected detector measurement summaries."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn


RUNTIME_PATH = "runtime_seconds"
BEHAVIORAL_PREFIXES = (
    "findings_by_detector_severity",
    "total_findings",
    "default_visible",
    "cap_hidden",
    "level_hidden",
    "known_example_ranks",
    "detectors_run",
    "detectors_skipped",
    "detectors_failed",
    "exit_code",
)
BEHAVIORAL_ALLOWLIST_COUNTS = frozenset({
    "allowlist_state.connections",
    "allowlist_state.domains",
    "allowlist_state.connection_total",
    "allowlist_state.domain_total",
})


class DiffError(ValueError):
    """A fail-closed summary comparison error."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser whose failures never echo path-bearing tokens."""

    def error(self, message: str) -> NoReturn:
        del message
        self.exit(2, "bench-diff: invalid arguments\n")


@dataclass(frozen=True)
class _EmptyContainer:
    kind: str


@dataclass(frozen=True)
class _Missing:
    pass


MISSING = _Missing()


def _child_path(path: str, child: str) -> str:
    return child if not path else f"{path}.{child}"


def _index_path(path: str, index: int) -> str:
    return f"{path}[{index}]"


def _flatten(value: Any, path: str = "", output: dict[str, Any] | None = None) -> dict[str, Any]:
    flat = {} if output is None else output
    if isinstance(value, dict):
        if not value:
            flat[path] = _EmptyContainer("dict")
        else:
            for key in sorted(value):
                if not isinstance(key, str):
                    raise DiffError("summary object keys must be strings")
                _flatten(value[key], _child_path(path, key), flat)
    elif isinstance(value, list):
        if not value:
            flat[path] = _EmptyContainer("list")
        else:
            for index, item in enumerate(value):
                _flatten(item, _index_path(path, index), flat)
    else:
        flat[path] = value
    return flat


def _same_leaf(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right


def _is_behavioral(path: str) -> bool:
    if path in BEHAVIORAL_ALLOWLIST_COUNTS:
        return True
    return any(
        path == prefix or path.startswith(prefix + ".") or path.startswith(prefix + "[")
        for prefix in BEHAVIORAL_PREFIXES
    )


def _validate_float_fields(flat: dict[str, Any]) -> None:
    for path, value in flat.items():
        if isinstance(value, float) and path != RUNTIME_PATH:
            raise DiffError(f"unexpected float field {path} — extend field-class map")


def _runtime_result(left: Any, right: Any) -> tuple[bool, float, float]:
    if type(left) is not float or type(right) is not float:
        raise DiffError("runtime_seconds must be a float in both summaries")
    delta = abs(left - right)
    tolerance = max(0.5, 0.50 * max(left, right))
    return delta <= tolerance, delta, tolerance


def _display(value: Any) -> str:
    if isinstance(value, _Missing):
        return "<missing>"
    if isinstance(value, _EmptyContainer):
        return f"<empty-{value.kind}>"
    return repr(value)


def _load_summary(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise DiffError("summary root must be an object")
    return value


def _compare(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    expect_diff: bool,
    strict_runtime: bool,
) -> tuple[int, list[str]]:
    if not isinstance(left.get("config_hash"), str) or not isinstance(right.get("config_hash"), str):
        raise DiffError("config_hash must be a string in both summaries")

    flat_left = _flatten(left)
    flat_right = _flatten(right)
    _validate_float_fields(flat_left)
    _validate_float_fields(flat_right)

    runtime_left = flat_left.get(RUNTIME_PATH, MISSING)
    runtime_right = flat_right.get(RUNTIME_PATH, MISSING)
    runtime_ok, runtime_delta, runtime_tolerance = _runtime_result(runtime_left, runtime_right)

    paths = sorted((set(flat_left) | set(flat_right)) - {RUNTIME_PATH})
    differences: list[tuple[str, Any, Any]] = []
    identical = 0
    for path in paths:
        a = flat_left.get(path, MISSING)
        b = flat_right.get(path, MISSING)
        if _same_leaf(a, b):
            identical += 1
        else:
            differences.append((path, a, b))

    hash_equal = _same_leaf(left["config_hash"], right["config_hash"])
    mode = "diff" if expect_diff or not hash_equal else "repeat"
    lines: list[str] = []

    if mode == "repeat":
        if differences:
            lines.append(f"not repeatable: {len(differences)} exact field differences")
            lines.extend(
                f"  {path}: {_display(a)} -> {_display(b)}" for path, a, b in differences
            )
        else:
            status = "within tol" if runtime_ok else "outside tol"
            lines.append(
                f"repeatable: {identical} fields identical, runtime "
                f"{runtime_left:.3f}s vs {runtime_right:.3f}s "
                f"(delta {runtime_delta:.3f}s, {status})"
            )
        failed = bool(differences) or (strict_runtime and not runtime_ok)
        if strict_runtime and not runtime_ok:
            lines.append(
                f"runtime outside tolerance: delta {runtime_delta:.3f}s > "
                f"{runtime_tolerance:.3f}s"
            )
        return (1 if failed else 0), lines

    context = "config unchanged — code/candidate diff" if hash_equal else "config changed"
    lines.append(f"diff: {context}")
    if differences:
        lines.extend(f"  {path}: {_display(a)} -> {_display(b)}" for path, a, b in differences)
    else:
        lines.append("  no exact field differences")
    runtime_status = "within tol" if runtime_ok else "outside tol"
    lines.append(
        f"  runtime: {runtime_left:.3f}s -> {runtime_right:.3f}s "
        f"(delta {runtime_delta:.3f}s, {runtime_status})"
    )

    behavioral = [path for path, _, _ in differences if _is_behavioral(path)]
    failed = False
    if expect_diff and not behavioral:
        lines.append("change produced no observable BEHAVIORAL change")
        failed = True
    if strict_runtime and not runtime_ok:
        lines.append(
            f"runtime outside tolerance: delta {runtime_delta:.3f}s > "
            f"{runtime_tolerance:.3f}s"
        )
        failed = True
    return (1 if failed else 0), lines


def _build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--expect-diff", action="store_true")
    parser.add_argument("--strict-runtime", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Compare two projected summaries and return the selected mode's status."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        left = _load_summary(args.left)
        right = _load_summary(args.right)
        code, lines = _compare(
            left,
            right,
            expect_diff=args.expect_diff,
            strict_runtime=args.strict_runtime,
        )
    except OSError:
        parser.exit(1, "bench-diff: could not read summaries\n")
    except json.JSONDecodeError:
        parser.exit(1, "bench-diff: could not parse summaries\n")
    except (DiffError, TypeError, ValueError):
        parser.exit(1, "bench-diff: comparison refused\n")
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
